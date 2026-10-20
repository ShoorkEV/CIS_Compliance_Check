#!/usr/bin/env bash
# lib/facts.sh - lazy, read-only fact collectors and parsed fact accessors.
#
# Every external command the audit runs lives in a collect_* function in this
# file. Collected output is cached as one file per fact in $FACTS_DIR. Checks
# never run commands; they call need <fact>... and read the parsed arrays.
#
# Test mode (CIS_AUDIT_FACTS_DIR set): facts are never collected, a missing fact
# file means "unavailable" and file reads go through the fixture root $R.
# shellcheck disable=SC2034

FACTS_DIR=""
FIXTURE_MODE=0
FACT_FILE=""
declare -A FACT_STATE=() FACT_ERR=()

# fact <name> [arg]  - make sure a fact is cached. Sets FACT_FILE.
fact() {
    local n=$1 arg=${2-} key
    key=$n
    [[ -n $arg ]] && key="$n.${arg//[^A-Za-z0-9._-]/_}"
    FACT_FILE="$FACTS_DIR/$key"
    case ${FACT_STATE[$key]-} in
        ok) return 0 ;;
        fail) return 1 ;;
    esac
    if [[ -e $FACT_FILE ]]; then
        FACT_STATE[$key]=ok
        return 0
    fi
    if (( FIXTURE_MODE )) || ! declare -F "collect_$n" >/dev/null; then
        FACT_STATE[$key]=fail
        FACT_ERR[$key]="not available in the facts directory"
        return 1
    fi
    log_verbose "collecting fact: $key"
    if "collect_$n" "$arg" >"$FACT_FILE.tmp" 2>"$FACT_FILE.err"; then
        mv -f -- "$FACT_FILE.tmp" "$FACT_FILE"
        FACT_STATE[$key]=ok
        return 0
    fi
    FACT_STATE[$key]=fail
    FACT_ERR[$key]=$(head -n1 "$FACT_FILE.err" 2>/dev/null)
    [[ -n ${FACT_ERR[$key]} ]] || FACT_ERR[$key]="command failed or timed out"
    rm -f -- "$FACT_FILE.tmp"
    return 1
}

# need <logical-fact>... : load facts for the current check or report ERROR.
need() {
    local x
    for x in "$@"; do
        if ! "need_$x"; then
            result "$CUR_ID" ERROR "required fact '$x' is unavailable: ${NEED_ERR:-unknown reason}"
            return 1
        fi
    done
    return 0
}
NEED_ERR=""
_need_fact() { # _need_fact <fact> [arg]
    if fact "$@"; then return 0; fi
    local key=$1
    [[ -n ${2-} ]] && key="$1.${2//[^A-Za-z0-9._-]/_}"
    NEED_ERR="$key: ${FACT_ERR[$key]-unknown}"
    return 1
}

# ----------------------------------------------------------- collectors ----
# Each collector prints the fact on stdout and returns 0 when the fact is usable.
find_bin() { # find_bin <name> -> BIN
    BIN=""
    local d
    for d in /usr/sbin /usr/bin /sbin /bin; do
        if [[ -x $d/$1 ]]; then BIN=$d/$1; return 0; fi
    done
    return 1
}

collect_dpkg() { tmo dpkg-query -W -f '${Package}\t${db:Status-Status}\t${Version}\n'; }
collect_unit_files() { tmo_tol systemctl list-unit-files --no-pager --no-legend; }
collect_units_all() { tmo_tol systemctl list-units --all --no-pager --no-legend --plain; }
collect_mounts() { tmo findmnt -knP -o TARGET,SOURCE,FSTYPE,OPTIONS; }
collect_sysctl_running() { tmo_tol sysctl -a 2>/dev/null; }
collect_sysctl_cat() {
    local b
    for b in /usr/lib/systemd/systemd-sysctl /lib/systemd/systemd-sysctl; do
        [[ -x $b ]] && { tmo "$b" --cat-config; return; }
    done
    return 1
}
collect_sshd_T() {
    find_bin sshd || return 1
    tmo "$BIN" -T
}
collect_sshd_T_C() {
    find_bin sshd || return 1
    tmo "$BIN" -T -C user=root,host=localhost,addr=127.0.0.1
}
collect_modprobe_cfg() { find_bin modprobe && tmo "$BIN" --showconfig; }
collect_lsmod() { tmo lsmod; }
collect_kmod_files() {
    tmo find /usr/lib/modules -type f \( -name '*.ko' -o -name '*.ko.*' \) \
        \( -path '*/kernel/fs/*' -o -path '*/kernel/net/*' \
        -o -path '*/kernel/drivers/firewire/*' -o -path '*/kernel/drivers/usb/storage/*' \) -print 2>/dev/null
    return 0
}
collect_ss_listen() { find_bin ss && tmo "$BIN" -plntuH; }
collect_ufw_status() { find_bin ufw && tmo "$BIN" status verbose; }
collect_apt_config() { find_bin apt-config || BIN=apt-config; tmo "$BIN" dump; }
collect_apt_policy() {
    tmo apt-cache policy libpam-runtime libpam-modules libpam-pwquality cracklib-runtime
}
collect_catcfg() { # systemd-analyze cat-config <name>
    local a
    for a in /usr/bin/systemd-analyze /bin/systemd-analyze; do
        [[ -x $a ]] && { tmo "$a" cat-config "$1"; return; }
    done
    return 1
}
collect_aa_status() {
    local b
    for b in /usr/sbin/apparmor_status /usr/sbin/aa-status; do
        [[ -x $b ]] && { tmo_tol "$b"; return 0; }
    done
    return 1
}
collect_ps_chronyd() { tmo ps -eo user:32=,args=; }
collect_root_path() {
    # root's login PATH without a PAM session: a login shell with a clean env
    tmo env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash TERM=dumb \
        /bin/bash -l -c 'printenv PATH' </dev/null
}
collect_mta_cfg() {
    local b out
    if find_bin postconf; then
        # effective value (postfix defaults to "all"), unlike the PDF's postconf -n
        out=$(tmo "$BIN" inet_interfaces) || return 1
        printf 'postconf: %s\n' "$out"
    elif find_bin exim || find_bin exim4; then
        out=$(tmo "$BIN" -bP local_interfaces) || return 1
        [[ $out == *=* && -n ${out#*=} && ${out#*=} != " " ]] || out="local_interfaces = all"
        printf 'exim: %s\n' "$out"
    elif find_bin sendmail && [[ -r /etc/mail/sendmail.cf ]]; then
        b=$(grep -i 'O DaemonPortOptions=' /etc/mail/sendmail.cf | grep -oP '(?<=Addr=)[^,+]+' | grep -v '^127\.0\.0\.1$')
        printf 'sendmail: %s\n' "$b"
    fi
    return 0
}
# 1.2.1.3 step 1: key files in the standard keyring dirs that are too permissive
collect_apt_keyfiles() {
    local f
    while IFS= read -r -d '' f; do
        stat -Lc '%a	%U	%G	%n' -- "$f"
    done < <(tmo find -L /usr/share/keyrings/ /etc/apt/trusted.gpg.d/ -mount -xdev -type f \
        \( ! -user root -o ! -group root -o -perm /133 \) -name '*gpg' -print0 2>/dev/null)
}
# 6.1.3.1: log files whose mode/owner/group might violate the rules (the benchmark's
# find criteria); the check applies the per-file rules.
collect_logfiles() {
    local f
    while IFS= read -r -d '' f; do
        stat -Lc '%a	%U	%G	%n' -- "$f"
    done < <(slow_tmo find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0 2>/dev/null)
}
# 3.1.2: kernel modules that drive wireless interfaces
collect_wireless_modules() {
    local d m
    for d in /sys/class/net/*/wireless; do
        [[ -d $d ]] || continue
        m=$(readlink -f "${d%/wireless}/device/driver/module" 2>/dev/null)
        [[ -n $m ]] && basename -- "$m"
    done
    return 0
}
# 7.2.10 / 7.2.11: dot files and dot directories in the home of every local
# interactive user: user, kind (f|d), mode, owner, group, path.
collect_home_dots() {
    local shells user home shell f kind mode owner grp
    shells=$(awk -F/ '$NF != "nologin" && /^\// {print}' /etc/shells)
    while IFS=: read -r user _ _ _ _ home shell; do
        [[ -n $user && -n $home && -n $shell ]] || continue
        grep -qxF -- "$shell" <<<"$shells" || continue
        [[ -d $home ]] || continue
        printf 'home\t%s\t%s\t%s\n' "$user" "$home" "$(findmnt -no FSTYPE --target "$home" 2>/dev/null)"
        for kind in f d; do
            while IFS= read -r -d '' f; do
                read -r mode owner grp < <(stat -Lc '%a %U %G' -- "$f")
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$user" "$mode" "$owner" "$grp" "$f"
            done < <(tmo find "$home" -xdev -type "$kind" -name '.*' -print0 2>/dev/null)
        done
    done </etc/passwd
}
# journald/rsyslog evidence for sudo events (5.2.3, read-only variant)
collect_sudo_log() {
    tmo_tol journalctl -t sudo -t sudo-rs -n 5 --no-pager -q 2>/dev/null
    return 0
}

slow_tmo() { timeout -k 3 "$((CHECK_TIMEOUT * ${SLOW_TIMEOUT_FACTOR:-5}))" "$@"; }

# Filesystem types the walks skip: the PDF's list (network, proc, vfat, iso9660, efivarfs,
# selinuxfs, ncpfs) plus the pseudo filesystems that `findmnt -D` hides in the PDF scripts.
WALK_SKIP_FS='nfs|proc|cifs|smb|vfat|iso9660|efivarfs|selinuxfs|ncpfs|sysfs|devtmpfs|devpts|cgroup|cgroup2|securityfs|debugfs|tracefs|configfs|fusectl|bpf|pstore|mqueue|hugetlbfs|autofs|binfmt_misc|rpc_pipefs|nsfs|squashfs|ramfs'

# Mount points a filesystem walk may visit: local filesystems only (7.1.11-7.1.13).
walk_mounts() { # walk_mounts <exclude-fstype-re> <exclude-target-re>
    local line t f
    while IFS= read -r line; do
        [[ $line =~ TARGET=\"([^\"]*)\".*FSTYPE=\"([^\"]*)\" ]] || continue
        t=${BASH_REMATCH[1]} f=${BASH_REMATCH[2]}
        [[ $f =~ ^($1) ]] && continue
        [[ $t =~ ^($2)(/|$) ]] && continue
        printf '%s\n' "$t"
    done < <(findmnt -knP -o TARGET,FSTYPE)
}

collect_fs_world() {
    local m f mode
    local -a prune=(-path '*/containers/storage/*' -o -path '*/containerd/*' -o -path '*/kubelet/*'
        -o -path '/sys/*' -o -path '/snap/*' -o -path '/boot/efi/*')
    while IFS= read -r m; do
        while IFS= read -r -d '' f; do
            [[ -e $f ]] || continue
            if [[ -f $f ]]; then
                printf 'f\t%s\n' "$f"
            elif [[ -d $f ]]; then
                mode=$(stat -Lc '%a' -- "$f")
                (( (8#$mode & 8#1000) == 0 )) && printf 'd\t%s\n' "$f"
            fi
        done < <(slow_tmo find "$m" -mount -xdev \( "${prune[@]}" \) -prune -o \( -type f -o -type d \) -perm -0002 -print0 2>/dev/null)
    done < <(walk_mounts "$WALK_SKIP_FS" '/run|/tmp|/var/tmp')
}
collect_fs_nouser() {
    local m f u g
    local -a prune=(-path '*/containers/storage/*' -o -path '*/containerd/*' -o -path '*/kubelet/*'
        -o -path '/sys/*' -o -path '/snap/*' -o -path '/boot/efi/*')
    while IFS= read -r m; do
        while IFS= read -r -d '' f; do
            [[ -e $f ]] || continue
            IFS=: read -r u g < <(stat -Lc '%U:%G' -- "$f")
            [[ $u == UNKNOWN ]] && printf 'u\t%s\n' "$f"
            [[ $g == UNKNOWN ]] && printf 'g\t%s\n' "$f"
        done < <(slow_tmo find "$m" -mount -xdev \( "${prune[@]}" \) -prune -o \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2>/dev/null)
    done < <(walk_mounts "$WALK_SKIP_FS" '/run|/tmp|/var/tmp')
}
collect_fs_suid() {
    local m f mode line t fs o
    while IFS= read -r line; do
        [[ $line =~ TARGET=\"([^\"]*)\".*FSTYPE=\"([^\"]*)\".*OPTIONS=\"([^\"]*)\" ]] || continue
        t=${BASH_REMATCH[1]} fs=${BASH_REMATCH[2]} o=${BASH_REMATCH[3]}
        [[ $fs =~ ^($WALK_SKIP_FS) ]] && continue
        [[ $t == /run/user/* ]] && continue
        [[ ,$o, == *,noexec,* || ,$o, == *,nosuid,* ]] && continue
        while IFS= read -r -d '' f; do
            [[ -e $f ]] || continue
            mode=$(stat -Lc '%a' -- "$f")
            (( 8#$mode & 8#4000 )) && printf 'suid\t%s\n' "$f"
            (( 8#$mode & 8#2000 )) && printf 'sgid\t%s\n' "$f"
        done < <(slow_tmo find "$t" -xdev -type f \( -perm -2000 -o -perm -4000 \) -print0 2>/dev/null)
    done < <(findmnt -knP -o TARGET,SOURCE,FSTYPE,OPTIONS)
}

# ------------------------------------------------------------ file access --
# fstat <path>: file metadata via stat -L (never lstat). Sets S_MODE (octal,
# no leading zero, includes setuid/sticky), S_USER, S_GROUP, S_TYPE (f|d|o).
# In test mode metadata comes from $FACTS_DIR/stat.tsv (path mode user group type);
# paths missing from that map take safe defaults if the fixture file exists.
declare -A STATMAP=()
STATMAP_LOADED=0
_fstat_raw() {
    local p=$1 line t
    S_MODE="" S_USER="" S_GROUP="" S_TYPE="" S_MODE4=""
    if (( FIXTURE_MODE )); then
        if (( ! STATMAP_LOADED )); then
            if [[ -r $FACTS_DIR/stat.tsv ]]; then
                local sp sm su sg st
                while IFS=$'\t' read -r sp sm su sg st; do
                    [[ -z $sp || $sp == \#* ]] && continue
                    STATMAP[$sp]="$sm $su $sg ${st:-f}"
                done <"$FACTS_DIR/stat.tsv"
            fi
            STATMAP_LOADED=1
        fi
        if [[ -n ${STATMAP[$p]+x} ]]; then
            read -r S_MODE S_USER S_GROUP S_TYPE <<<"${STATMAP[$p]}"
            [[ $S_MODE == - ]] && return 1     # explicitly absent
            return 0
        fi
        if [[ -d $R$p ]]; then
            S_MODE=755 S_USER=root S_GROUP=root S_TYPE=d
            return 0
        elif [[ -e $R$p ]]; then
            S_MODE=644 S_USER=root S_GROUP=root S_TYPE=f
            return 0
        fi
        return 1
    fi
    line=$(stat -Lc '%a %U %G %F' -- "$p" 2>/dev/null) || return 1
    read -r S_MODE S_USER S_GROUP t <<<"$line"
    case $t in
        *directory*) S_TYPE=d ;;
        *regular*) S_TYPE=f ;;
        *) S_TYPE=o ;;
    esac
    return 0
}

fstat() {
    _fstat_raw "$1" || return 1
    printf -v S_MODE4 '%04o' "$((8#$S_MODE))"
}

# fexists <path> (honours test-mode absent entries)
fexists() { fstat "$1"; }

# --------------------------------------------------------- parsed facts ----
declare -A PKG_STATE=() PKG_VER=()
need_dpkg() {
    [[ -n ${LOADED_dpkg-} ]] && return 0
    _need_fact dpkg || return 1
    local p s v
    while IFS=$'\t' read -r p s v; do
        [[ -n $p ]] || continue
        PKG_STATE[$p]=$s PKG_VER[$p]=$v
    done <"$FACT_FILE"
    LOADED_dpkg=1
}
pkg_installed() { [[ ${PKG_STATE[$1]-} == installed ]]; }

declare -A UNIT_FILE_STATE=() UNIT_ACTIVE=() UNIT_LOAD=()
need_unit_files() {
    [[ -n ${LOADED_unit_files-} ]] && return 0
    _need_fact unit_files || return 1
    local u s rest
    while read -r u s rest; do
        [[ -n $u ]] && UNIT_FILE_STATE[$u]=$s
    done <"$FACT_FILE"
    LOADED_unit_files=1
}
need_units() {
    need_unit_files || return 1
    [[ -n ${LOADED_units-} ]] && return 0
    _need_fact units_all || return 1
    local u load act rest
    while read -r u load act rest; do
        [[ $u == ●* ]] && { read -r u load act rest <<<"$load $act $rest"; }
        [[ -n $u ]] && { UNIT_LOAD[$u]=$load; UNIT_ACTIVE[$u]=$act; }
    done <"$FACT_FILE"
    LOADED_units=1
}
unit_is_enabled() { [[ ${UNIT_FILE_STATE[$1]-} == enabled* ]]; }
unit_is_active() { [[ ${UNIT_ACTIVE[$1]-} == active ]]; }
unit_describe() { # -> REPLY "enabled-state/active-state"
    REPLY="${UNIT_FILE_STATE[$1]:-not-found}/${UNIT_ACTIVE[$1]:-inactive}"
}

declare -A MNT_OPTS=() MNT_FSTYPE=() MNT_SRC=()
MNT_TARGETS=()
need_mounts() {
    [[ -n ${LOADED_mounts-} ]] && return 0
    _need_fact mounts || return 1
    local line
    while IFS= read -r line; do
        if [[ $line =~ TARGET=\"([^\"]*)\"\ SOURCE=\"([^\"]*)\"\ FSTYPE=\"([^\"]*)\"\ OPTIONS=\"([^\"]*)\" ]]; then
            MNT_OPTS[${BASH_REMATCH[1]}]=${BASH_REMATCH[4]}
            MNT_FSTYPE[${BASH_REMATCH[1]}]=${BASH_REMATCH[3]}
            MNT_SRC[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
            MNT_TARGETS+=("${BASH_REMATCH[1]}")
        fi
    done <"$FACT_FILE"
    LOADED_mounts=1
}
# mount_for_path <path> -> REPLY = fstype of the mount containing the path
mount_fstype_for() {
    local p=$1 best="" t
    for t in "${MNT_TARGETS[@]}"; do
        if [[ $p == "$t" || $p == "${t%/}"/* ]]; then
            (( ${#t} > ${#best} )) && best=$t
        fi
    done
    REPLY=${MNT_FSTYPE[$best]-}
}

declare -A SYSCTL_RUN=() SYSCTL_PERSIST=() SYSCTL_PERSIST_FILE=() SYSCTL_ALL=() UFW_SYSCTL=()
sysctl_key() { # normalise a/b/c -> a.b.c
    REPLY=${1//\//.}
}
need_sysctl() {
    [[ -n ${LOADED_sysctl-} ]] && return 0
    _need_fact sysctl_running || return 1
    local k v line file
    while IFS= read -r line; do
        [[ $line =~ ^([^[:space:]=]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
        SYSCTL_RUN[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
    done <"$FACT_FILE"
    _need_fact sysctl_cat || return 1
    file=""
    while IFS= read -r line; do
        if [[ $line =~ ^[[:space:]]*#[[:space:]]*(/[^#[:space:]]+\.conf)$ ]]; then
            file=${BASH_REMATCH[1]}
            continue
        fi
        [[ $line =~ ^[[:space:]]*[#\;] ]] && continue
        if [[ $line =~ ^[[:space:]]*-?([^[:space:]=]+)[[:space:]]*=[[:space:]]*([^[:space:]].*)$ ]]; then
            sysctl_key "${BASH_REMATCH[1]}"
            k=$REPLY
            v=${BASH_REMATCH[2]}
            v=${v%"${v##*[![:space:]]}"}
            SYSCTL_PERSIST[$k]=$v
            SYSCTL_PERSIST_FILE[$k]=$file
            SYSCTL_ALL[$k]+="${file}: $v"$'\n'
        fi
    done <"$FACT_FILE"
    # ufw applies its own sysctl file when it is enabled; it is loaded last.
    local ufwconf=$R/etc/ufw/ufw.conf ufwdef=$R/etc/default/ufw ufwsys="/etc/ufw/sysctl.conf" l
    if [[ -r $ufwdef ]]; then
        l=$(grep -Poi '^\s*IPT_SYSCTL=\K\S+' -- "$ufwdef" | tail -n1)
        l=${l//\"/}
        [[ -n $l ]] && ufwsys=$l
    fi
    UFW_SYSCTL_FILE=$ufwsys
    UFW_ENABLED=0
    [[ -r $ufwconf ]] && grep -Pqi '^\s*ENABLED\s*=\s*yes\b' -- "$ufwconf" && UFW_ENABLED=1
    if (( UFW_ENABLED )) && [[ -r $R$ufwsys ]]; then
        while IFS= read -r line; do
            [[ $line =~ ^[[:space:]]*[#\;] ]] && continue
            if [[ $line =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
                sysctl_key "${BASH_REMATCH[1]}"
                UFW_SYSCTL[$REPLY]=${BASH_REMATCH[2]}
            fi
        done <"$R$ufwsys"
    fi
    LOADED_sysctl=1
}

declare -A SSHD=()
need_sshd() {
    [[ -n ${LOADED_sshd-} ]] && return 0
    _need_fact sshd_T || return 1
    local k v line
    while IFS= read -r line; do
        k=${line%% *}
        v=${line#* }
        [[ $line == *" "* ]] || v=""
        SSHD["base:$k"]=$v
        SSHD["baseall:$k"]+="$v"$'\n'
    done <"$FACT_FILE"
    SSHD_HAS_MATCH=0
    if grep -Pqsi '^\s*Match\s+(User|Group|Host|LocalAddress|LocalPort|Address)\b' -- "$R/etc/ssh/sshd_config" "$R"/etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
        SSHD_HAS_MATCH=1
        if fact sshd_T_C; then
            while IFS= read -r line; do
                k=${line%% *}
                v=${line#* }
                [[ $line == *" "* ]] || v=""
                SSHD["match:$k"]=$v
            done <"$FACT_FILE"
        fi
    fi
    LOADED_sshd=1
}

declare -A MOD_BLACKLIST=() MOD_INSTALL=() LSMOD=()
need_modprobe() {
    [[ -n ${LOADED_modprobe-} ]] && return 0
    _need_fact modprobe_cfg || return 1
    local kw a b rest
    while read -r kw a b rest; do
        a=${a//-/_}
        case $kw in
            blacklist) MOD_BLACKLIST[$a]=1 ;;
            install) MOD_INSTALL[$a]="$b${rest:+ $rest}" ;;
        esac
    done <"$FACT_FILE"
    LOADED_modprobe=1
}
need_lsmod() {
    [[ -n ${LOADED_lsmod-} ]] && return 0
    _need_fact lsmod || return 1
    local m rest
    while read -r m rest; do
        [[ $m == Module ]] && continue
        LSMOD[${m//-/_}]=1
    done <"$FACT_FILE"
    LOADED_lsmod=1
}
need_kmod() { _need_fact kmod_files; }
need_ss() { _need_fact ss_listen; }
need_ufw() { _need_fact ufw_status; }
need_aptcfg() { _need_fact apt_config; }
need_aptpol() { _need_fact apt_policy; }

# ------------------------------------------------- systemd cat-config -------
# catcfg_get <name> <section> <key>
#  Sets CC_VALUE/CC_FILE/CC_DEFAULT/CC_ALL from `systemd-analyze cat-config`.
#  The last uncommented assignment wins. CC_DEFAULT holds the first commented
#  "#Key=Value" default in the section, as the benchmark's scripts read it.
catcfg_get() {
    local name=$1 section=$2 key=$3 line file="" cur="" k v
    CC_VALUE="" CC_FILE="" CC_DEFAULT="" CC_ALL=""
    _need_fact catcfg "$name" || return 1
    while IFS= read -r line; do
        if [[ $line =~ ^[[:space:]]*#[[:space:]]*(/[^#[:space:]]+\.conf)[[:space:]]*$ ]]; then
            file=${BASH_REMATCH[1]}
            continue
        fi
        if [[ $line =~ ^[[:space:]]*\[([^]]+)\][[:space:]]*$ ]]; then
            cur=${BASH_REMATCH[1]}
            continue
        fi
        [[ $cur == "$section" ]] || continue
        if [[ $line =~ ^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            k=${BASH_REMATCH[1]} v=${BASH_REMATCH[2]}
            if [[ ${k,,} == "${key,,}" ]]; then
                v=${v%%#*}
                v=${v%"${v##*[![:space:]]}"}
                CC_VALUE=$v CC_FILE=$file
                CC_ALL+="$file: $key=$v"$'\n'
            fi
        elif [[ -z $CC_DEFAULT && $line =~ ^[[:space:]]*#[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            if [[ ${BASH_REMATCH[1],,} == "${key,,}" ]]; then
                CC_DEFAULT=${BASH_REMATCH[2]}
                CC_DEFAULT=${CC_DEFAULT%"${CC_DEFAULT##*[![:space:]]}"}
            fi
        fi
    done <"$FACT_FILE"
    return 0
}

# --------------------------------------------------------------- misc -------
os_release_get() { # os_release_get KEY -> REPLY (no sourcing)
    local line v
    REPLY=""
    [[ -r $R/etc/os-release ]] || return 1
    while IFS= read -r line; do
        if [[ $line =~ ^$1=(.*)$ ]]; then
            v=${BASH_REMATCH[1]}
            v=${v#\"}
            v=${v%\"}
            REPLY=$v
            return 0
        fi
    done <"$R/etc/os-release"
    return 1
}
