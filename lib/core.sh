#!/usr/bin/env bash
# lib/core.sh - shared state, result recording, logging and small helpers.
# Sourced by cis-audit.sh. Defines functions and default globals only.
# shellcheck disable=SC2034  # globals are consumed by the other libs

CIS_VERSION="1.0.0"
CIS_BENCH_NAME="CIS Ubuntu Linux 26.04 LTS Benchmark"
CIS_BENCH_VERSION="v1.0.0"

# bash 5.2 turns "&" in a ${var//pat/repl} replacement into the matched text.
shopt -u patsub_replacement 2>/dev/null || true

# ---------------------------------------------------------------- state ----
VALID_STATES=" PASS FAIL EXCEPTION MANUAL N/A SKIPPED ERROR "
declare -A R_STATE=() R_EVID=() R_NOTE=()   # per control id
declare -A EXC_JUST=() EXC_BY=() EXC_EXP=() # exceptions by id
declare -A SITE=()                          # site.conf values
declare -A P=()                             # params of the control being run
CHECK_TIMEOUT=60
VERBOSE=0
QUIET=0
USE_COLOR=0
R=""                                        # root prefix for file reads (tests only)
[[ -n ${CIS_AUDIT_TESTMODE-} ]] && R=${CIS_AUDIT_ROOTFS:-}
CUR_ID=""

# --------------------------------------------------------------- output ----
init_colors() {
    C_RED="" C_GRN="" C_YEL="" C_BLU="" C_DIM="" C_RST=""
    if (( USE_COLOR )); then
        C_RED=$'\e[31m' C_GRN=$'\e[32m' C_YEL=$'\e[33m' C_BLU=$'\e[34m'
        C_DIM=$'\e[2m' C_RST=$'\e[0m'
    fi
}

log_err()  { printf 'cis-audit: %s\n' "$*" >&2; }
log_warn() { (( QUIET )) || printf 'cis-audit: warning: %s\n' "$*" >&2; }
log_info() { (( QUIET )) || printf '%s\n' "$*" >&2; }
log_verbose() { (( VERBOSE )) && printf '%s\n' "$*" >&2; return 0; }

# Usage/precondition errors end the run with exit code 3.
die_usage() {
    log_err "$*"
    exit 3
}

# ------------------------------------------------------------- results ----
# result <ID> <STATE> <evidence line>...
# Every check ends with exactly one call. Evidence says what was found and what
# was expected.
result() {
    local id=$1 state=$2
    shift 2
    if [[ $VALID_STATES != *" $state "* ]]; then
        state=ERROR
        set -- "internal error: invalid state requested for $id"
    fi
    if (( $# == 0 )); then
        set -- "(check returned no evidence)"
    fi
    # An evidence line starting with "!" is a finding: it is moved to the front
    # (marker removed) so the reason for a FAIL is the first line an admin reads.
    local e
    local -a first=() rest=()
    for e in "$@"; do
        if [[ $e == '!'* ]]; then first+=("${e:1}"); else rest+=("$e"); fi
    done
    local IFS=$'\n'
    R_STATE[$id]=$state
    R_EVID[$id]="${first[*]}${first[*]:+$'\n'}${rest[*]}"
    RESULT_SET=1
}

# Run one check with a clean result flag; a check that forgets to call result()
# is reported as ERROR rather than silently dropped.
run_check_fn() {
    local fn=$1 id=$2
    RESULT_SET=0
    "$fn" "$id"
    if (( ! RESULT_SET )); then
        result "$id" ERROR "check function $fn did not report a result"
    fi
}

# ------------------------------------------------------------- helpers -----
tmo() { timeout -k 3 "$CHECK_TIMEOUT" "$@"; }

# Like tmo, but only a timeout (124) or a missing binary (127) is a failure.
tmo_tol() {
    tmo "$@"
    local rc=$?
    (( rc == 124 || rc == 127 )) && return 1
    return 0
}

trim() {
    local s=$1
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    REPLY=$s
}

is_uint() { [[ ${1-} =~ ^[0-9]+$ ]]; }
is_int()  { [[ ${1-} =~ ^-?[0-9]+$ ]]; }

# list_has "a,b,c" item  (separator "," or "|")
list_has() {
    local list=$1 item=$2 x
    local IFS=',|'
    for x in $list; do
        [[ $x == "$item" ]] && return 0
    done
    return 1
}

# oct_excess <actual-octal> <max-octal>: prints the permission bits in actual
# that are not allowed by max (as octal). Returns 0 when nothing is excess.
oct_excess() {
    local a=$((8#${1:-0})) m=$((8#${2:-0})) x
    x=$(( a & ~m & 07777 ))
    printf -v OCT_EX '%04o' "$x"
    (( x == 0 ))
}

# mode4 <octal>: M4 = the mode as four octal digits ("0644"). No subshell.
mode4() { printf -v M4 '%04o' "$((8#${1:-0}))"; }

# html_escape <string>  -> REPLY. One helper for every value taken from the host.
html_escape() {
    local s=$1
    s=${s//&/'&amp;'}
    s=${s//</'&lt;'}
    s=${s//>/'&gt;'}
    s=${s//\"/'&quot;'}
    s=${s//\'/'&#39;'}
    REPLY=$s
}

# Replace control characters in text that came from the host (log files and
# usernames may hold anything) so reports cannot carry terminal escapes.
sanitize() {
    REPLY=${1//[^[:print:]$'\n'$'\t']/?}
}

# Resolve "@NAME:default" parameter values against site.conf.
site_val() {
    local name=$1 def=$2
    REPLY=${SITE[$name]:-$def}
}

# Parse "k=v;k=v" into the global P array. Values may contain "=" (first one splits).
parse_params() {
    local spec=$1 kv k v
    P=()
    [[ -z $spec || $spec == "-" ]] && return 0
    local IFS=';'
    for kv in $spec; do
        k=${kv%%=*}
        v=${kv#*=}
        [[ $kv == *=* ]] || v=""
        if [[ $v == @*:* ]]; then
            local nm=${v#@} df=${v#*:}
            nm=${nm%%:*}
            site_val "$nm" "$df"
            v=$REPLY
        fi
        P[$k]=$v
    done
}

# Calendar helpers without date(1): days since 1970-01-01 for YYYY-MM-DD.
days_from_civil() {
    local y=$1 m=$2 d=$3 era yoe doy doe
    m=$((10#$m)) d=$((10#$d))
    (( m <= 2 )) && y=$((y - 1))
    era=$(( (y >= 0 ? y : y - 399) / 400 ))
    yoe=$(( y - era * 400 ))
    doy=$(( (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1 ))
    doe=$(( yoe * 365 + yoe / 4 - yoe / 100 + doy ))
    REPLY=$(( era * 146097 + doe - 719468 ))
}

valid_date() {
    [[ ${1-} =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})$ ]] || return 1
    local y=${BASH_REMATCH[1]} m=$((10#${BASH_REMATCH[2]})) d=$((10#${BASH_REMATCH[3]}))
    (( m >= 1 && m <= 12 && d >= 1 && d <= 31 )) || return 1
    local dim=(0 31 28 31 30 31 30 31 31 30 31 30 31)
    if (( m == 2 )) && { (( y % 4 == 0 && y % 100 != 0 )) || (( y % 400 == 0 )); }; then
        dim[2]=29
    fi
    (( d <= dim[m] ))
}

# Read a file's lines with comments and blanks removed; prints to stdout.
strip_comments() {
    local f=$1
    [[ -r $f ]] || return 1
    grep -Pv '^\s*(#|$)' -- "$f"
}

# Sort IDs like 1.2.10 after 1.2.9
sort_ids() { LC_ALL=C sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -k5,5n; }

# Truncate for one-line display
trunc() {
    local s=$1 n=$2
    if (( ${#s} > n )); then
        REPLY="${s:0:n-3}..."
    else
        REPLY=$s
    fi
}
