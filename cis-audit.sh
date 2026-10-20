#!/usr/bin/env bash
# cis-audit.sh - read-only CIS Ubuntu Linux 26.04 LTS Benchmark v1.0.0 audit
# (Level 1 - Server). Writes a text and an HTML report. Never changes the system.
#
#   cis-audit.sh --help
#
# Internal compliance check, not an official CIS-CAT result. CIS benchmark content
# is licensed for internal use only.
set -o pipefail
set -u

export LC_ALL=C
if [[ -z ${CIS_AUDIT_TESTMODE-} ]]; then
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)

# @@LIBS_BEGIN - tools/build_single.sh replaces this block with the library sources
for _lib in core facts applicability checks_generic \
    checks_custom/s1_initial_setup checks_custom/s2_services checks_custom/s3_network \
    checks_custom/s4_firewall checks_custom/s5_access checks_custom/s6_logging \
    checks_custom/s7_maintenance exceptions report_text report_html; do
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/lib/$_lib.sh" || { echo "cis-audit: cannot load lib/$_lib.sh" >&2; exit 3; }
done
unset _lib
# @@LIBS_END

# ---------------------------------------------------------------- catalog --
CATALOG_COLS=10
declare -A CAT_TITLE=() CAT_ASSESS=() CAT_SRV=() CAT_WS=() CAT_TYPE=() CAT_PARAMS=() CAT_APPLIES=() CAT_SLOW=() CAT_STATUS=()
CAT_IDS=()
KNOWN_TYPES=" sysctl file_perm svc_not_in_use sshd_param mount_opt conf_kv kmod_unavailable pam_module pkg_installed pkg_absent gdm svc_enabled_active file_perm_glob apt_config mount_tmpfs_or_separate manual custom - "

# @@CATALOG_BEGIN - tools/build_single.sh defines catalog_embedded() here
catalog_embedded() { return 1; }
# @@CATALOG_END

catalog_stream() { # prints the catalog TSV
    if catalog_embedded 2>/dev/null; then return 0; fi
    cat -- "$CATALOG_FILE"
}

catalog_load() {
    local id title assess srv ws type params applies slow status n=0 hdr=1
    CATALOG_FILE=$SCRIPT_DIR/catalog/controls.tsv
    [[ -n ${CIS_AUDIT_TESTMODE-} && -n ${CIS_AUDIT_CATALOG-} ]] && CATALOG_FILE=$CIS_AUDIT_CATALOG
    if ! catalog_embedded >/dev/null 2>&1 && [[ ! -r $CATALOG_FILE ]]; then
        die_usage "catalog $CATALOG_FILE is not readable"
    fi
    while IFS=$'\t' read -r id title assess srv ws type params applies slow status; do
        n=$((n + 1))
        if (( hdr )); then
            [[ $id == id && $status == status ]] || die_usage "catalog: bad header line"
            hdr=0
            continue
        fi
        [[ $id =~ ^[0-9]+(\.[0-9]+)+$ ]] || die_usage "catalog line $n: bad id '$id'"
        [[ -z ${CAT_TYPE[$id]+x} ]] || die_usage "catalog line $n: duplicate id $id"
        [[ $srv =~ ^([12]|-)$ && $ws =~ ^([12]|-)$ ]] || die_usage "catalog line $n ($id): bad level"
        [[ $KNOWN_TYPES == *" $type "* ]] || die_usage "catalog line $n ($id): unknown check_type '$type'"
        [[ $slow =~ ^[01]$ && $status =~ ^(done|todo)$ && $assess =~ ^(Automated|Manual)$ ]] || die_usage "catalog line $n ($id): bad field"
        CAT_IDS+=("$id")
        CAT_TITLE[$id]=$title CAT_ASSESS[$id]=$assess CAT_SRV[$id]=$srv CAT_WS[$id]=$ws CAT_TYPE[$id]=$type
        CAT_PARAMS[$id]=$params CAT_APPLIES[$id]=$applies CAT_SLOW[$id]=$slow CAT_STATUS[$id]=$status
    done < <(catalog_stream)
    (( ${#CAT_IDS[@]} > 0 )) || die_usage "catalog is empty"
}

# ------------------------------------------------------------------ usage --
usage() {
    cat <<EOF
cis-audit $CIS_VERSION - read-only audit against the $CIS_BENCH_NAME $CIS_BENCH_VERSION

Usage: cis-audit.sh [options]
  --level N             cumulative level to audit (default 1; 2 reports Level 2 rows as NOT IMPLEMENTED)
  --profile server      benchmark profile (only 'server' in v1)
  --section LIST        comma list of ID prefixes to run, e.g. 1,5.3
  --only LIST           comma list of ID prefixes; only these run, e.g. 5.1.7,6.3.2
  --skip LIST           comma list of ID prefixes reported as SKIPPED (wins over --only)
  --config FILE         site configuration (default /etc/cis-audit/site.conf if present)
  --exceptions FILE     accepted deviations (default /etc/cis-audit/exceptions.conf if present)
  --output DIR          report directory (default ./cis-audit-reports, mode 0700)
  --format LIST         text,html (default both)
  --no-slow             skip filesystem walks (rows marked slow), reported as SKIPPED
  --timeout SECONDS     time limit per external command (default 60)
  --verbose             print evidence for every control on screen
  --quiet               print nothing except errors
  --no-color            no colour on screen
  --force-os            do not stop on an OS other than Ubuntu 26.04
  --list                print the filtered catalog and exit 0 without auditing
  --version             print the version
  --help                this text

Exit codes: 0 no FAIL and no ERROR, 1 at least one FAIL, 2 no FAIL but at least one
ERROR (audit incomplete), 3 usage or precondition error (not root, wrong OS, invalid
configuration, exceptions or options).
The audit is read-only. It writes only to the report directory and a private temp dir.
EOF
}

# ------------------------------------------------------------- arguments --
OPT_LEVEL=1 OPT_PROFILE=server OPT_SECTION="" OPT_ONLY="" OPT_SKIP="" OPT_CONFIG="" OPT_EXC=""
OPT_OUTPUT="./cis-audit-reports" OPT_FORMAT="text,html" OPT_NOSLOW=0 OPT_FORCE_OS=0 OPT_LIST=0 OPT_NOCOLOR=0
OPTS_GIVEN=""

parse_args() {
    local a v
    OPTS_GIVEN="$*"
    [[ -z $OPTS_GIVEN ]] && OPTS_GIVEN="(none)"
    while (( $# )); do
        a=$1
        shift
        case $a in
            --level=*|--profile=*|--section=*|--only=*|--skip=*|--config=*|--exceptions=*|--output=*|--format=*|--timeout=*)
                set -- "${a%%=*}" "${a#*=}" "$@"
                continue ;;
        esac
        case $a in
            --help|-h) usage; exit 0 ;;
            --version) echo "cis-audit $CIS_VERSION ($CIS_BENCH_NAME $CIS_BENCH_VERSION)"; exit 0 ;;
            --list) OPT_LIST=1 ;;
            --no-slow) OPT_NOSLOW=1 ;;
            --verbose) VERBOSE=1 ;;
            --quiet) QUIET=1 ;;
            --no-color) OPT_NOCOLOR=1 ;;
            --force-os) OPT_FORCE_OS=1 ;;
            --level|--profile|--section|--only|--skip|--config|--exceptions|--output|--format|--timeout)
                (( $# )) || die_usage "option $a needs a value"
                v=$1
                shift
                case $a in
                    --level) OPT_LEVEL=$v ;;
                    --profile) OPT_PROFILE=$v ;;
                    --section) OPT_SECTION=$v ;;
                    --only) OPT_ONLY=$v ;;
                    --skip) OPT_SKIP=$v ;;
                    --config) OPT_CONFIG=$v ;;
                    --exceptions) OPT_EXC=$v ;;
                    --output) OPT_OUTPUT=$v ;;
                    --format) OPT_FORMAT=$v ;;
                    --timeout) CHECK_TIMEOUT=$v ;;
                esac ;;
            *) usage >&2; die_usage "unknown option: $a" ;;
        esac
    done
    [[ $OPT_LEVEL =~ ^[12]$ ]] || die_usage "--level must be 1 or 2"
    case $OPT_PROFILE in
        server) PROFILE_LABEL=Server ;;
        workstation) die_usage "--profile workstation is not supported in v1 (only 'server')" ;;
        *) die_usage "--profile must be 'server'" ;;
    esac
    is_uint "$CHECK_TIMEOUT" && (( CHECK_TIMEOUT > 0 )) || die_usage "--timeout must be a positive number of seconds"
    local f
    local -a fmts
    IFS=',' read -ra fmts <<<"$OPT_FORMAT"
    for f in "${fmts[@]}"; do
        [[ $f == text || $f == html ]] || die_usage "--format accepts text and html (got '$f')"
    done
    LEVEL=$OPT_LEVEL
}

# prefix lists
in_prefixes() { # in_prefixes <comma list> <id>
    local p
    local -a ps
    IFS=',' read -ra ps <<<"$1"
    for p in "${ps[@]}"; do
        [[ -z $p ]] && continue
        [[ $2 == "$p" || $2 == "$p".* ]] && return 0
    done
    return 1
}

validate_prefixes() { # every given prefix must match at least one catalog id
    local name=$1 list=$2 p id hit
    local -a ps
    [[ -z $list ]] && return 0
    IFS=',' read -ra ps <<<"$list"
    for p in "${ps[@]}"; do
        [[ $p =~ ^[0-9]+(\.[0-9]+)*$ ]] || die_usage "$name: '$p' is not a control id or id prefix"
        hit=0
        for id in "${CAT_IDS[@]}"; do
            [[ $id == "$p" || $id == "$p".* ]] && { hit=1; break; }
        done
        (( hit )) || die_usage "$name: no control matches '$p'"
    done
}

select_rows() {
    SEL_IDS=()
    local id srv
    for id in "${CAT_IDS[@]}"; do
        srv=${CAT_SRV[$id]}
        [[ $srv == - ]] && continue
        (( srv <= LEVEL )) || continue
        [[ -n $OPT_SECTION ]] && ! in_prefixes "$OPT_SECTION" "$id" && continue
        [[ -n $OPT_ONLY ]] && ! in_prefixes "$OPT_ONLY" "$id" && continue
        SEL_IDS+=("$id")
    done
}

# -------------------------------------------------------------- preflight --
preflight() {
    if (( BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 2) )); then
        die_usage "bash 5.2 or newer is required (found $BASH_VERSION)"
    fi
    # CIS_AUDIT_TESTMODE (tests only) skips the root check; the OS check always runs
    # and reads $R/etc/os-release, which is the fixture's file in test runs.
    if [[ -z ${CIS_AUDIT_TESTMODE-} ]]; then
        (( EUID == 0 )) || die_usage "must run as root (needed for /etc/shadow, /etc/gshadow and sshd -T)"
    fi
    local osid="" osver=""
    os_release_get ID && osid=$REPLY
    os_release_get VERSION_ID && osver=$REPLY
    if [[ $osid != ubuntu || $osver != 26.04 ]]; then
        if (( OPT_FORCE_OS )); then
            log_warn "OS is '${osid:-unknown} ${osver:-unknown}', not Ubuntu 26.04; continuing because of --force-os"
        else
            die_usage "this audit is for Ubuntu 26.04 (found '${osid:-unknown} ${osver:-unknown}'); use --force-os to run anyway"
        fi
    fi
}

hash_of() { # hash_of <file> -> REPLY
    if [[ -n $1 && -r $1 ]]; then
        REPLY=$(sha256sum -- "$1" 2>/dev/null | awk '{print $1}')
    else
        REPLY="(not used)"
    fi
}

# ----------------------------------------------------------------- running --
run_one() {
    local id=$1 type fn why
    CUR_ID=$id
    type=${CAT_TYPE[$id]}
    R_NOTE[$id]=""
    if [[ -n $OPT_SKIP ]] && in_prefixes "$OPT_SKIP" "$id"; then
        result "$id" SKIPPED "excluded with --skip"
        return
    fi
    if [[ ${CAT_STATUS[$id]} == todo ]]; then
        result "$id" SKIPPED "NOT IMPLEMENTED: this recommendation belongs to a later release (Level ${CAT_SRV[$id]} - Server)"
        return
    fi
    if (( OPT_NOSLOW )) && [[ ${CAT_SLOW[$id]} == 1 ]]; then
        result "$id" SKIPPED "skipped by --no-slow (full filesystem walk)"
        return
    fi
    if [[ ${CAT_APPLIES[$id]} != - ]]; then
        applies "${CAT_APPLIES[$id]}"
        case $? in
            0) ;;
            1) result "$id" N/A "not applicable: $APPLIES_WHY"; return ;;
            *) result "$id" ERROR "cannot decide applicability: $APPLIES_WHY"; return ;;
        esac
    fi
    parse_params "${CAT_PARAMS[$id]}"
    case $type in
        custom) fn="cus_${id//./_}" ;;
        *) fn="chk_$type" ;;
    esac
    if ! declare -F "$fn" >/dev/null; then
        result "$id" ERROR "no check function $fn for check type $type"
        return
    fi
    run_check_fn "$fn" "$id"
}

print_result_line() {
    local id=$1 st=${R_STATE[$1]} col="" line
    case $st in
        PASS) col=$C_GRN ;;
        FAIL|ERROR) col=$C_RED ;;
        MANUAL|EXCEPTION) col=$C_YEL ;;
        *) col=$C_DIM ;;
    esac
    printf '%s[%s]%s %s %s\n' "$col" "$st" "$C_RST" "$id" "${CAT_TITLE[$id]}"
    if (( VERBOSE )); then
        sanitize "${R_EVID[$id]}"
        while IFS= read -r line; do
            [[ -n $line ]] && printf '    %s\n' "$line"
        done <<<"$REPLY"
    fi
}

host_info() {
    local line
    HOST_NAME=$(head -n1 "$R/proc/sys/kernel/hostname" 2>/dev/null)
    [[ -n $HOST_NAME ]] || HOST_NAME=$(hostname 2>/dev/null)
    [[ -n $HOST_NAME ]] || HOST_NAME=unknown
    HOST_FQDN=$HOST_NAME
    # FQDN without DNS: look for a dotted alias of the host in /etc/hosts
    if [[ $HOST_NAME != *.* && -r $R/etc/hosts ]]; then
        while IFS= read -r line; do
            [[ $line =~ ^[[:space:]]*# ]] && continue
            if [[ $line =~ [[:space:]]($HOST_NAME\.[^[:space:]]+) ]]; then
                HOST_FQDN=${BASH_REMATCH[1]}
                break
            fi
        done <"$R/etc/hosts"
    fi
    if [[ -r $R/proc/sys/kernel/ostype && -r $R/proc/sys/kernel/osrelease ]]; then
        KERNEL="$(<"$R/proc/sys/kernel/ostype") $(<"$R/proc/sys/kernel/osrelease")"
    else
        KERNEL=$(uname -sr 2>/dev/null) || KERNEL=unknown
    fi
    os_release_get PRETTY_NAME && OS_PRETTY=$REPLY || OS_PRETTY=unknown
}

main() {
    local id n=0 total out_base ts fmt f
    parse_args "$@"
    CIS_START_EPOCH=$EPOCHSECONDS
    if [[ -t 1 && $OPT_NOCOLOR -eq 0 && -z ${NO_COLOR-} ]]; then USE_COLOR=1; fi
    init_colors
    catalog_load
    validate_prefixes --section "$OPT_SECTION"
    validate_prefixes --only "$OPT_ONLY"
    validate_prefixes --skip "$OPT_SKIP"
    select_rows

    if (( OPT_LIST )); then
        for id in "${SEL_IDS[@]}"; do
            printf '%s\t%s\t%s\t%s\n' "$id" "${CAT_SRV[$id]}" "${CAT_TYPE[$id]}" "${CAT_TITLE[$id]}"
        done
        exit 0
    fi

    preflight
    local cfg=${OPT_CONFIG:-} exc=${OPT_EXC:-}
    [[ -z $cfg && -r $R/etc/cis-audit/site.conf ]] && cfg=/etc/cis-audit/site.conf
    [[ -z $exc && -r $R/etc/cis-audit/exceptions.conf ]] && exc=/etc/cis-audit/exceptions.conf
    [[ -n $cfg ]] && site_load "$cfg"
    [[ -n $exc ]] && exceptions_load "$exc"

    # private temp dir, removed on exit; report dir is the only other write target
    umask 077
    TMPD=$(mktemp -d "${TMPDIR:-/tmp}/cis-audit.XXXXXXXX") || die_usage "cannot create a temp directory"
    trap 'rm -rf -- "$TMPD"' EXIT
    if [[ -n ${CIS_AUDIT_TESTMODE-} && -n ${CIS_AUDIT_FACTS_DIR-} ]]; then
        FACTS_DIR=$CIS_AUDIT_FACTS_DIR FIXTURE_MODE=1
    else
        FACTS_DIR=$TMPD/facts
        mkdir -m 0700 "$FACTS_DIR" || die_usage "cannot create $FACTS_DIR"
    fi
    mkdir -p -m 0700 -- "$OPT_OUTPUT" || die_usage "cannot create report directory $OPT_OUTPUT"

    host_info
    printf -v RUN_START '%(%Y-%m-%d %H:%M:%S)T' -1
    TODAY=${RUN_START%% *}
    total=${#SEL_IDS[@]}
    log_info "cis-audit $CIS_VERSION: auditing $HOST_NAME against $CIS_BENCH_NAME $CIS_BENCH_VERSION, Level $LEVEL $PROFILE_LABEL ($total controls)"

    RUN_IDS=()
    local progress=0
    [[ -t 2 ]] && (( ! QUIET && ! VERBOSE )) && progress=1
    for id in "${SEL_IDS[@]}"; do
        n=$((n + 1))
        (( progress )) && printf '\r  checking %d/%d  %-12s' "$n" "$total" "$id" >&2
        run_one "$id"
        RUN_IDS+=("$id")
        if (( VERBOSE && ! QUIET )); then
            print_result_line "$id"
        fi
    done
    (( progress )) && printf '\r%40s\r' '' >&2

    exceptions_apply
    printf -v RUN_END '%(%Y-%m-%d %H:%M:%S)T' -1
    RUN_SECONDS=$((EPOCHSECONDS - CIS_START_EPOCH))
    hash_of "${CATALOG_FILE:-}"
    if catalog_embedded >/dev/null 2>&1; then
        SHA_CATALOG=$(catalog_embedded | sha256sum | awk '{print $1}')
    else
        SHA_CATALOG=$REPLY
    fi
    hash_of "${cfg:+$R$cfg}"; SHA_SITE=$REPLY
    hash_of "${exc:+$R$exc}"; SHA_EXC=$REPLY
    report_prepare

    printf -v ts '%(%Y%m%d-%H%M%S)T' -1
    out_base="$OPT_OUTPUT/cis-audit_${HOST_NAME//[^A-Za-z0-9._-]/_}_$ts"
    local -a written=()
    IFS=',' read -ra fmts <<<"$OPT_FORMAT"
    for fmt in "${fmts[@]}"; do
        case $fmt in
            text) report_text "$out_base.txt" && written+=("$out_base.txt") ;;
            html) report_html "$out_base.html" && written+=("$out_base.html") ;;
        esac
    done

    if (( ! QUIET )); then
        printf 'Summary for %s (Level %s %s): ' "$HOST_NAME" "$LEVEL" "$PROFILE_LABEL"
        local s
        for s in "${REPORT_STATES[@]}"; do printf '%s=%s ' "$s" "${CNT[$s]}"; done
        printf 'score=%s\n' "$SCORE_ALL"
        for f in "${written[@]}"; do printf 'report: %s\n' "$f"; done
    fi

    if (( CNT[FAIL] > 0 )); then exit 1; fi
    if (( CNT[ERROR] > 0 )); then exit 2; fi
    exit 0
}

main "$@"
