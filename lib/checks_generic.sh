#!/usr/bin/env bash
# lib/checks_generic.sh - the 15 generic check types.
#
# Contract: chk_<type> <ID> reads its parameters from the global P array (set from
# the catalog row) and the parsed facts, and ends with exactly one `result` call.
# No command is run here; only fact accessors from facts.sh are used.
# shellcheck disable=SC2034,SC2154

# ------------------------------------------------------------- helpers ----
pget() { REPLY=${P[$1]-${2-}}; }

# expand_glob <pattern>: GLOB = existing paths (without the test root prefix)
expand_glob() {
    local pat=$1 f
    GLOB=()
    if [[ $pat != *[*?[]* ]]; then
        fexists "$pat" && GLOB=("$pat")
        return 0
    fi
    shopt -s nullglob
    for f in $R$pat; do
        GLOB+=("${f#"$R"}")
    done
    shopt -u nullglob
}

# perm_eval <path> <max-mode> <owners a|b> <groups a|b>
# Appends to PERM_OK / PERM_BAD. Returns 1 when the path does not exist.
perm_eval() {
    local p=$1 max=$2 owners=$3 groups=$4 ex bad=""
    fstat "$p" || return 1
    mode4 "$max"
    local max4=$M4
    oct_excess "$S_MODE" "$max" || bad="mode $S_MODE4 grants $OCT_EX beyond allowed $max4"
    list_has "$owners" "$S_USER" || bad+="${bad:+, }owner $S_USER, expected ${owners//|/ or }"
    list_has "$groups" "$S_GROUP" || bad+="${bad:+, }group $S_GROUP, expected ${groups//|/ or }"
    if [[ -n $bad ]]; then
        PERM_BAD+=("$p: $bad")
    else
        PERM_OK+=("$p: mode $S_MODE4 owner $S_USER group $S_GROUP (max $max4, ${owners//|/ or }:${groups//|/ or })")
    fi
    return 0
}

# strip one pair of surrounding double quotes
unquote() { REPLY=${1#\"}; REPLY=${REPLY%\"}; }

# val_ok <op> <expected> <actual>   (numeric and string comparisons)
val_ok() {
    local op=$1 exp=$2 act=$3
    unquote "$act"
    act=$REPLY
    case $op in
        eq) [[ ${act,,} == "${exp,,}" ]] ;;
        ne) [[ ${act,,} != "${exp,,}" ]] ;;
        oneof) list_has "${exp,,}" "${act,,}" ;;
        le) is_int "$act" && (( act <= exp )) ;;
        lt) is_int "$act" && (( act < exp )) ;;
        ge) is_int "$act" && (( act >= exp )) ;;
        gt) is_int "$act" && (( act > exp )) ;;
        range) is_int "$act" && (( act >= ${exp%-*} && act <= ${exp#*-} )) ;;
        range1) is_int "$act" && (( act >= 1 && act <= exp )) ;;
        zero_or_ge) is_int "$act" && (( act == 0 || act >= exp )) ;;
        set) [[ -n $act ]] ;;
        *) return 2 ;;
    esac
}

# op_text <op> <expected> -> REPLY, a readable form of a comparison
op_text() {
    case $1 in
        eq) REPLY="$2" ;;
        ne) REPLY="anything but $2" ;;
        oneof) REPLY="one of ${2//,/, }" ;;
        le) REPLY="$2 or less" ;;
        lt) REPLY="less than $2" ;;
        ge) REPLY="$2 or more" ;;
        gt) REPLY="greater than $2" ;;
        range) REPLY="${2%-*} to ${2#*-}" ;;
        range1) REPLY="1 to $2" ;;
        zero_or_ge) REPLY="0 (never) or $2 or more" ;;
        set) REPLY="a value" ;;
        flag) REPLY="the option present" ;;
        *) REPLY="$1 $2" ;;
    esac
}

# ---------------------------------------------------------------- sysctl ---
chk_sysctl() {
    local id=$1 key=${P[key]-} vals=${P[values]:-${P[value]-}} run persisted src exp
    local -a good=() bad=()
    need sysctl || return
    exp=${vals//,/ or }
    if [[ -z ${SYSCTL_RUN[$key]+x} ]]; then
        bad+=("$key: not present in the running kernel (sysctl -a), expected $exp")
    else
        run=${SYSCTL_RUN[$key]}
        run=${run%"${run##*[![:space:]]}"}
        run=${run//[[:space:]]/ }
        if list_has "${vals// /,}" "$run"; then
            good+=("$key: running=$run, expected $exp")
        else
            bad+=("$key: running=$run, expected $exp")
        fi
    fi
    if [[ -n ${UFW_SYSCTL[$key]+x} ]]; then
        persisted=${UFW_SYSCTL[$key]} src="$UFW_SYSCTL_FILE (ufw is enabled and applies it last)"
    elif [[ -n ${SYSCTL_PERSIST[$key]+x} ]]; then
        persisted=${SYSCTL_PERSIST[$key]} src=${SYSCTL_PERSIST_FILE[$key]}
    else
        persisted="" src=""
    fi
    if [[ -z $persisted ]]; then
        bad+=("$key: persisted=not set in any file read by systemd-sysctl (a reboot would reset it), expected $exp")
    elif list_has "${vals// /,}" "$persisted"; then
        good+=("$key: persisted=$persisted ($src), expected $exp")
    else
        bad+=("$key: persisted=$persisted ($src), expected $exp")
        [[ -n ${SYSCTL_ALL[$key]-} ]] && bad+=("all assignments seen by systemd-sysctl (last wins): ${SYSCTL_ALL[$key]//$'\n'/; }")
    fi
    if (( ${#bad[@]} )); then result "$id" FAIL "${bad[@]}" "${good[@]}"; else result "$id" PASS "${good[@]}"; fi
}

# ------------------------------------------------------------- file_perm ---
chk_file_perm() {
    local id=$1 spec=${P[path]-} max=${P[mode]-} owners=${P[owner]:-root} groups=${P[group]:-root}
    local missing=${P[missing]:-fail} one found=0
    local -a paths ev=() PERM_OK=() PERM_BAD=() lst
    case ${P[dyn]-} in
        pam_motd) dyn_pam_motd_paths ;;
        sshd_banner) dyn_sshd_banner_paths ;;
        *) IFS=',' read -ra paths <<<"$spec" ;;
    esac
    if [[ -n ${P[dyn]-} ]]; then
        paths=("${DYN_PATHS[@]}")
        if (( ${#paths[@]} == 0 )); then
            result "$id" PASS "${DYN_NONE_MSG:-no file configured; nothing to check}"
            return
        fi
    fi
    for one in "${paths[@]}"; do
        expand_glob "$one"
        lst=("${GLOB[@]}")
        if (( ${#lst[@]} == 0 )); then
            ev+=("$one: does not exist")
            if [[ $missing == fail ]]; then PERM_BAD+=("$one: does not exist"); fi
            continue
        fi
        for found in "${lst[@]}"; do
            perm_eval "$found" "$max" "$owners" "$groups"
        done
    done
    if (( ${#PERM_BAD[@]} )); then
        result "$id" FAIL "${PERM_BAD[@]}" "${PERM_OK[@]}"
    elif (( ${#PERM_OK[@]} )); then
        result "$id" PASS "${PERM_OK[@]}" "${ev[@]}"
    elif [[ $missing == na ]]; then
        result "$id" N/A "${ev[@]}"
    else
        result "$id" PASS "${ev[@]}" "(nothing to check; benchmark treats a missing path as passing)"
    fi
}

chk_file_perm_glob() {
    local id=$1
    case ${P[source]-glob} in
        sshd_hostkey) chk_sshd_hostkeys "$id" ;;
        *)
            P[path]="${P[dir]%/}/${P[pattern]:-*}"
            P[missing]=${P[missing]:-pass}
            chk_file_perm "$id"
            ;;
    esac
}

# 5.1.3 / 5.1.4: host key files listed by sshd -T
chk_sshd_hostkeys() {
    local id=$1 k suffix=${P[suffix]-} max=${P[mode]-} line
    local -a keys=() PERM_OK=() PERM_BAD=() ev=()
    need sshd || return
    while IFS= read -r line; do
        [[ -n $line ]] && keys+=("$line$suffix")
    done <<<"${SSHD[baseall:hostkey]-}"
    if (( ${#keys[@]} == 0 )); then
        result "$id" PASS "sshd -T lists no hostkey entries; nothing to check"
        return
    fi
    for k in "${keys[@]}"; do
        if ! perm_eval "$k" "$max" "${P[owner]:-root}" "${P[group]:-root}"; then
            ev+=("$k: listed by sshd -T but does not exist (not checked)")
        fi
    done
    if (( ${#PERM_BAD[@]} )); then
        result "$id" FAIL "${PERM_BAD[@]}" "${PERM_OK[@]}"
    else
        result "$id" PASS "${PERM_OK[@]}" "${ev[@]}"
    fi
}

# dynamic path sets for 1.6.9 / 1.6.10
dyn_pam_motd_paths() {
    DYN_PATHS=() DYN_NONE_MSG="no motd= argument is set on a pam_motd line in /etc/pam.d"
    local f m
    shopt -s nullglob
    for f in $R/etc/pam.d/*; do
        [[ -f $f ]] || continue
        while IFS= read -r m; do
            m=${m#\"}; m=${m%\"}; m=${m#\'}; m=${m%\'}
            [[ -n $m ]] && DYN_PATHS+=("$m")
        done < <(grep -hPo 'motd=\K\S+' -- "$f" 2>/dev/null)
    done
    shopt -u nullglob
    if (( ${#DYN_PATHS[@]} )); then
        mapfile -t DYN_PATHS < <(printf '%s\n' "${DYN_PATHS[@]}" | LC_ALL=C sort -u)
    fi
}
dyn_sshd_banner_paths() {
    DYN_PATHS=() DYN_NONE_MSG="sshd -T shows no Banner file (rule 1.6.5 covers the missing directive)"
    need sshd || return
    local b=${SSHD[base:banner]-}
    if [[ $b == /* ]]; then DYN_PATHS=("$b"); fi
}

# ------------------------------------------------------- svc_not_in_use ----
# pkg_match_installed <pattern-list>: sets PKG_HITS to installed packages that
# match any entry (entries may end in *).
pkg_match_installed() {
    local list=$1 e p
    PKG_HITS=()
    local -a ents
    IFS=',' read -ra ents <<<"$list"
    for e in "${ents[@]}"; do
        [[ -z $e ]] && continue
        if [[ $e == *'*' ]]; then
            for p in "${!PKG_STATE[@]}"; do
                [[ $p == ${e} && ${PKG_STATE[$p]} == installed ]] && PKG_HITS+=("$p")
            done
        elif pkg_installed "$e"; then
            PKG_HITS+=("$e")
        fi
    done
}

chk_svc_not_in_use() {
    local id=$1 pkgs=${P[pkgs]-} units=${P[units]-} u d
    local -a ev=() act=() ents
    need dpkg units || return
    pkg_match_installed "$pkgs"
    if [[ -n $pkgs ]] && (( ${#PKG_HITS[@]} == 0 )); then
        result "$id" PASS "none of the packages (${pkgs//,/, }) is installed"
        return
    fi
    IFS=',' read -ra ents <<<"$units"
    for u in "${ents[@]}"; do
        [[ -z $u ]] && continue
        unit_describe "$u"
        d=$REPLY
        if unit_is_enabled "$u" || unit_is_active "$u"; then
            act+=("$u: $d (enabled-state/active-state), expected neither enabled nor active")
        else
            ev+=("$u: $d (not enabled, not active)")
        fi
    done
    local pk="no package"
    (( ${#PKG_HITS[@]} )) && pk="installed: ${PKG_HITS[*]}"
    if (( ${#act[@]} )); then
        result "$id" FAIL "$pk" "${act[@]}" "${ev[@]}"
    else
        result "$id" PASS "$pk; the service units are neither enabled nor active" "${ev[@]}"
    fi
}

# -------------------------------------------------------- svc_enabled_active
chk_svc_enabled_active() {
    local id=$1 want=${P[need]:-enabled,active} spec=${P[unit]-} u pick="" d
    local -a ents
    need units || return
    IFS='|' read -ra ents <<<"$spec"
    for u in "${ents[@]}"; do
        if [[ -n ${UNIT_FILE_STATE[$u]+x} || -n ${UNIT_ACTIVE[$u]+x} ]]; then pick=$u; break; fi
    done
    [[ -n $pick ]] || pick=${ents[0]}
    unit_describe "$pick"
    d=$REPLY
    local bad=0
    list_has "$want" enabled && ! unit_is_enabled "$pick" && bad=1
    list_has "$want" active && ! unit_is_active "$pick" && bad=1
    if (( bad )); then
        result "$id" FAIL "$pick: ${d} (enabled-state/active-state), expected ${want//,/ and }"
    else
        result "$id" PASS "$pick: ${d} (enabled-state/active-state), expected ${want//,/ and }"
    fi
}

# --------------------------------------------------------------- sshd ------
# Words the benchmark calls weak, per 5.1.7 / 5.1.13 / 5.1.17.
sshd_value() { # sshd_value <ctx> <key> -> REPLY (empty + rc 1 when absent)
    if [[ -n ${SSHD["$1:$2"]+x} ]]; then REPLY=${SSHD["$1:$2"]}; return 0; fi
    REPLY=""
    return 1
}

banner_re() {
    os_release_get ID
    local osid=${REPLY:-ubuntu}
    BANNER_RE='(\\v|\\r|\\m|\\s|\b'"${osid//\"/}"'\b)'
}

# sshd_rule <ctx> <key> <op> <value>; appends to SR_OK / SR_BAD
sshd_rule() {
    local ctx=$1 key=$2 op=$3 exp=$4 v tok a b c
    local label="$key"
    [[ $ctx == match ]] && label="$key (Match evaluated for user=root,host=localhost,addr=127.0.0.1)"
    if ! sshd_value "$ctx" "$key"; then
        SR_BAD+=("$label: not reported by sshd -T")
        return
    fi
    v=$REPLY
    unquote "$v"
    v=$REPLY
    case $op in
        none_of)
            local -a toks weak
            IFS=',' read -ra toks <<<"$v"
            IFS=',' read -ra weak <<<"$exp"
            local hits=()
            for tok in "${toks[@]}"; do
                for a in "${weak[@]}"; do
                    [[ ${tok,,} == "${a,,}" ]] && hits+=("$tok")
                done
            done
            if (( ${#hits[@]} )); then
                SR_BAD+=("$label: weak entries in use: ${hits[*]}")
            else
                SR_OK+=("$label: no weak entries (value: $v)")
            fi
            ;;
        maxstartups)
            IFS=: read -r a b c <<<"$v"
            local ea eb ec
            IFS=: read -r ea eb ec <<<"$exp"
            if is_int "$a" && (( a <= ea )) && { [[ -z $b ]] || { is_int "$b" && (( b <= eb )); }; } && { [[ -z $c ]] || { is_int "$c" && (( c <= ec )); }; }; then
                SR_OK+=("$label: $v, expected $exp or more restrictive")
            else
                SR_BAD+=("$label: $v, expected $exp or more restrictive")
            fi
            ;;
        *)
            if val_ok "$op" "$exp" "$v"; then
                op_text "$op" "$exp"; SR_OK+=("$label: $v, expected $REPLY")
            else
                op_text "$op" "$exp"; SR_BAD+=("$label: $v, expected $REPLY")
            fi
            ;;
    esac
}

chk_sshd_param() {
    local id=$1 ctx sfx rk rop rv
    local -a SR_OK=() SR_BAD=() ctxs=(base)
    need sshd || return
    (( SSHD_HAS_MATCH )) && [[ -n ${SSHD[match:permitrootlogin]+x} ]] && ctxs+=(match)
    case ${P[op]-} in
        anyset)
            local k found=0 shown=""
            local -a ks
            IFS=',' read -ra ks <<<"${P[key]-}"
            for k in "${ks[@]}"; do
                if [[ -n ${SSHD[base:$k]-} ]]; then found=1; shown+="$k ${SSHD[base:$k]}; "; fi
            done
            if (( found )); then
                result "$id" PASS "access directive set: ${shown%; }" "review the lists against site policy"
            else
                result "$id" FAIL "none of ${P[key]//,/, } is set in the effective sshd configuration, expected at least one"
            fi
            return
            ;;
        banner)
            sshd_banner_rule
            ;;
        *)
            for sfx in "" 2 3; do
                rk=${P[key$sfx]-}
                [[ -z $rk ]] && continue
                rop=${P[op$sfx]} rv=${P[value$sfx]-}
                for ctx in "${ctxs[@]}"; do sshd_rule "$ctx" "$rk" "$rop" "$rv"; done
            done
            ;;
    esac
    # 5.1.19: MaxSessions must also not exceed the limit in the config files
    if [[ ${P[key]-} == maxsessions ]]; then
        local f hit
        for f in "$R/etc/ssh/sshd_config" "$R"/etc/ssh/sshd_config.d/*.conf; do
            [[ -r $f ]] || continue
            hit=$(grep -Pio -- '^\s*MaxSessions\s+"?\K[0-9]+' "$f" | awk -v max="${P[value]-}" '$1+0>max+0')
            [[ -n $hit ]] && SR_BAD+=("${f#"$R"}: MaxSessions $hit exceeds ${P[value]-}")
        done
    fi
    if (( ${#SR_BAD[@]} )); then
        result "$id" FAIL "${SR_BAD[@]}" "${SR_OK[@]}"
    else
        result "$id" PASS "${SR_OK[@]}"
    fi
}

# 1.6.5 / 5.1.6: Banner set, file exists, no OS information in it
sshd_banner_rule() {
    local ctx b hits
    banner_re
    for ctx in base; do
        sshd_value "$ctx" banner || { SR_BAD+=("banner: not reported by sshd -T"); continue; }
        b=$REPLY
        if [[ $b != /* ]]; then
            SR_BAD+=("banner: '${b:-unset}', expected a file path such as /etc/issue.net")
            continue
        fi
        if [[ ! -r $R$b ]]; then
            SR_BAD+=("banner: file $b is not readable or does not exist")
            continue
        fi
        hits=$(grep -Pi -- "$BANNER_RE" "$R$b" | head -n 3)
        if [[ -n $hits ]]; then
            SR_BAD+=("banner file $b contains OS information or escape codes (\\m \\r \\s \\v or the OS name): $hits")
        else
            SR_OK+=("banner $b: set, no OS information; content must still match site policy")
        fi
        if [[ -n ${SITE[BANNER_FILE]-} && -r $R${SITE[BANNER_FILE]} ]]; then
            if cmp -s -- "$R$b" "$R${SITE[BANNER_FILE]}"; then
                SR_OK+=("banner $b matches site banner ${SITE[BANNER_FILE]}")
            else
                SR_BAD+=("banner $b differs from the site banner ${SITE[BANNER_FILE]}")
            fi
        fi
    done
}

# --------------------------------------------------------------- mounts ----
chk_mount_opt() {
    local id=$1 path=${P[path]-} opt=${P[opt]-} o
    need mounts || return
    if [[ -z ${MNT_OPTS[$path]+x} ]]; then
        result "$id" N/A "$path is not a separate mount point; the benchmark applies this only to a separate partition"
        return
    fi
    o=${MNT_OPTS[$path]}
    if [[ ,$o, == *,"$opt",* ]]; then
        result "$id" PASS "$path (${MNT_FSTYPE[$path]}): options $o include $opt"
    else
        result "$id" FAIL "$path (${MNT_FSTYPE[$path]}): options $o do not include $opt"
    fi
}

chk_mount_tmpfs_or_separate() {
    local id=$1 path=${P[path]-} unit=${P[unit]-} st
    local -a ev=()
    need mounts || return
    if [[ -z ${MNT_OPTS[$path]+x} ]]; then
        result "$id" FAIL "$path is not a mount point (neither tmpfs nor a separate partition)"
        return
    fi
    ev+=("$path is mounted: ${MNT_SRC[$path]} (${MNT_FSTYPE[$path]}) ${MNT_OPTS[$path]}")
    if [[ -n $unit ]]; then
        need unit_files || return
        st=${UNIT_FILE_STATE[$unit]-not-listed}
        case $st in
            masked|masked-runtime|disabled)
                result "$id" FAIL "${ev[@]}" "$unit is $st; systemd would not mount $path at boot"
                return ;;
        esac
        ev+=("$unit unit state: $st (not masked or disabled)")
    fi
    result "$id" PASS "${ev[@]}"
}

# ------------------------------------------------------ kmod_unavailable ---
chk_kmod_unavailable() {
    local id=$1 name=${P[name]-} dir=${P[dir]-} n
    local -a ev=()
    need kmod modprobe lsmod || return
    n=${name//-/_}
    if ! grep -qs -- "/kernel/$dir/" "$FACTS_DIR/kmod_files"; then
        result "$id" PASS "no kernel/$dir module directory under /usr/lib/modules: $name is built in or absent"
        return
    fi
    ev+=("module files for $name exist under kernel/$dir; checking that it is not loaded and not loadable")
    local bad=0
    if [[ -n ${LSMOD[$n]+x} ]]; then
        ev+=("!$name is currently loaded (lsmod), expected not loaded"); bad=1
    else
        ev+=("$name is not loaded (lsmod)")
    fi
    if [[ -n ${MOD_BLACKLIST[$n]+x} ]]; then
        ev+=("blacklist $n is configured")
    else
        ev+=("!missing 'blacklist $n' in modprobe configuration"); bad=1
    fi
    local inst=${MOD_INSTALL[$n]-}
    if [[ $inst == /bin/false || $inst == /bin/true ]]; then
        ev+=("install $n $inst is configured")
    else
        ev+=("!missing 'install $n /bin/false' (or /bin/true) in modprobe configuration${inst:+; found: install $n $inst}"); bad=1
    fi
    result "$id" "$( (( bad )) && echo FAIL || echo PASS)" "${ev[@]}"
}

# ----------------------------------------------------------- packages ------
chk_pkg_absent() {
    local id=$1
    need dpkg || return
    pkg_match_installed "${P[pkgs]-}"
    if (( ${#PKG_HITS[@]} )); then
        result "$id" FAIL "installed: ${PKG_HITS[*]}, expected none of ${P[pkgs]//,/, }"
    else
        result "$id" PASS "none of ${P[pkgs]//,/, } is installed"
    fi
}

# pkgs_satisfied <comma list, entries may be a|b> -> sets PKS_MSG
pkgs_satisfied() {
    local list=$1 e alt got rc=0
    local -a ents alts
    PKS_MSG=""
    IFS=',' read -ra ents <<<"$list"
    for e in "${ents[@]}"; do
        got=""
        IFS='|' read -ra alts <<<"$e"
        for alt in "${alts[@]}"; do
            pkg_installed "$alt" && { got=$alt; break; }
        done
        if [[ -n $got ]]; then
            PKS_MSG+="$got ${PKG_VER[$got]} installed; "
        else
            PKS_MSG+="${e//|/ or } NOT installed; "
            rc=1
        fi
    done
    return $rc
}

# apt_pkg_status <pkg> -> APT_INST APT_CAND from local apt-cache policy data
apt_pkg_status() {
    local line cur="" want=$1
    APT_INST="" APT_CAND=""
    while IFS= read -r line; do
        if [[ $line =~ ^([^[:space:]]+):[[:space:]]*$ ]]; then
            cur=${BASH_REMATCH[1]}
        elif [[ $cur == "$want" && $line =~ ^[[:space:]]+Installed:[[:space:]]*(.*)$ ]]; then
            APT_INST=${BASH_REMATCH[1]}
        elif [[ $cur == "$want" && $line =~ ^[[:space:]]+Candidate:[[:space:]]*(.*)$ ]]; then
            APT_CAND=${BASH_REMATCH[1]}
        fi
    done <"$FACT_FILE"
}

chk_pkg_installed() {
    local id=$1 ok=1 msg
    local -a ev=()
    need dpkg || return
    pkgs_satisfied "${P[pkgs]-}" || ok=0
    msg=$PKS_MSG
    if (( ! ok )) && [[ -n ${P[alt]-} ]]; then
        if pkgs_satisfied "${P[alt]-}"; then ok=1; msg="alternative set: $PKS_MSG"; fi
    fi
    if (( ok )); then ev+=("${msg%; }"); else ev+=("!${msg%; }, expected installed"); fi
    if (( ok )) && [[ ${P[latest]-0} == 1 ]]; then
        need aptpol || return
        local e alt
        local -a ents alts
        IFS=',' read -ra ents <<<"${P[pkgs]-}"
        for e in "${ents[@]}"; do
            IFS='|' read -ra alts <<<"$e"
            for alt in "${alts[@]}"; do
                pkg_installed "$alt" || continue
                apt_pkg_status "$alt"
                if [[ -z $APT_CAND || $APT_CAND == "(none)" || $APT_CAND == "$APT_INST" ]]; then
                    ev+=("$alt: installed $APT_INST is the newest version known to the local apt cache (no network check)")
                else
                    ev+=("!$alt: installed $APT_INST, candidate $APT_CAND in the local apt cache: upgrade available")
                    ok=0
                fi
                break
            done
        done
    fi
    result "$id" "$( (( ok )) && echo PASS || echo FAIL)" "${ev[@]}"
}

# --------------------------------------------------------- apt_config ------
chk_apt_config() {
    local id=$1 key=${P[key]-} exp=${P[value]-} line v
    need aptcfg || return
    line=$(grep -Pi -- "^\s*${key}\s+" "$FACT_FILE" | tail -n1)
    if [[ -z $line ]]; then
        result "$id" FAIL "$key is not set in 'apt-config dump', expected $key \"$exp\";"
        return
    fi
    v=$(sed -E 's/^[^"]*"([^"]*)".*/\1/' <<<"$line")
    if list_has "${P[accept]:-$exp}" "${v,,}"; then
        result "$id" PASS "$line (expected $exp)"
    else
        result "$id" FAIL "$line (expected $exp)"
    fi
}

# ---------------------------------------------------------------- gdm ------
chk_gdm() {
    result "$1" MANUAL "gdm3 is installed; this GDM setting is not automated in v1" \
        "Decision required: run the gsettings commands from the benchmark audit for ${1} (${P[key]-gdm}) and confirm the setting is locked and meets policy"
}

# ------------------------------------------------------------- manual ------
chk_manual() {
    local id=$1 fn="man_ev_${1//./_}"
    local -a ev=()
    if declare -F "$fn" >/dev/null; then
        mapfile -t ev < <("$fn")
    fi
    result "$id" MANUAL "${ev[@]}" "Decision required: ${P[hint]:-review against site policy}"
}

# ---------------------------------------------------------- pam_module -----
# pam_lines <file> <module> -> PAM_LINES (uncommented lines mentioning the module)
pam_lines() {
    local f=$R/etc/pam.d/$1 line
    PAM_LINES=()
    [[ -r $f ]] || return 1
    while IFS= read -r line; do
        [[ $line =~ ^[[:space:]]*# ]] && continue
        [[ $line =~ (^|[^[:alnum:]_])${2//./\\.}([^[:alnum:]_]|$) ]] && PAM_LINES+=("$line")
    done <"$f"
    return 0
}

# pam_args_of <line> <module> -> REPLY: the arguments after the module name
pam_args_of() {
    local l=$1 m=${2//./\\.}
    if [[ $l =~ $m[[:space:]]*(.*)$ ]]; then REPLY=${BASH_REMATCH[1]}; else REPLY=""; fi
}

# arg_value <args> <key> -> REPLY ("" + rc 1 when key not given)
arg_value() {
    local a
    for a in $1; do
        if [[ $a == "$2="* ]]; then REPLY=${a#*=}; return 0; fi
    done
    REPLY=""
    return 1
}
has_arg() { local a; for a in $1; do [[ $a == "$2" ]] && return 0; done; return 1; }

chk_pam_module() {
    local id=$1 mod=${P[module]-} mode=${P[mode]-} f l
    local -a files bad=() ok=() ev=()
    IFS=',' read -ra files <<<"${P[files]-}"
    case $mode in
        present_all)
            local need_arg
            for f in "${files[@]}"; do
                if ! pam_lines "$f" "$mod"; then bad+=("/etc/pam.d/$f: cannot be read"); continue; fi
                if (( ${#PAM_LINES[@]} == 0 )); then bad+=("/etc/pam.d/$f: no active $mod line"); continue; fi
                ok+=("/etc/pam.d/$f: ${PAM_LINES[0]}")
            done
            # required arguments per file, "file:arg|file:arg"
            if [[ -n ${P[args]-} ]]; then
                local pair pf pa found
                local -a pairs
                IFS='|' read -ra pairs <<<"${P[args]-}"
                for pair in "${pairs[@]}"; do
                    pf=${pair%%:*} pa=${pair#*:}
                    [[ -z $pa ]] && continue
                    found=0
                    pam_lines "$pf" "$mod" || continue
                    for l in "${PAM_LINES[@]}"; do has_arg "$l" "$pa" && found=1; done
                    (( found )) || bad+=("/etc/pam.d/$pf: no $mod line with argument '$pa'")
                done
            fi
            ;;
        forbid_arg)
            local rx=${P[argre]-}
            for f in "${files[@]}"; do
                pam_lines "$f" "$mod" || continue
                for l in "${PAM_LINES[@]}"; do
                    pam_args_of "$l" "$mod"
                    if grep -Pq -- "(^|\s)($rx)(\s|\$)" <<<"$REPLY"; then
                        bad+=("/etc/pam.d/$f: $l")
                    else
                        ok+=("/etc/pam.d/$f: no forbidden argument ($rx) on: $l")
                    fi
                done
            done
            ;;
        require_arg)
            local rx=${P[argre]-} typ=${P[type]:-password} seen=0
            for f in "${files[@]}"; do
                pam_lines "$f" "$mod" || { bad+=("/etc/pam.d/$f: cannot be read"); continue; }
                for l in "${PAM_LINES[@]}"; do
                    [[ $l =~ ^[[:space:]]*$typ[[:space:]] ]] || continue
                    seen=1
                    pam_args_of "$l" "$mod"
                    if grep -Pq -- "(^|\s)($rx)(\s|\$)" <<<"$REPLY"; then
                        ok+=("/etc/pam.d/$f: $l")
                    else
                        bad+=("/etc/pam.d/$f: $l does not include $rx")
                    fi
                done
            done
            (( seen )) || bad+=("no active $typ line for $mod in ${P[files]-}")
            ;;
        conf_or_arg)
            pam_conf_or_arg
            return
            ;;
    esac
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# pwhistory: value or flag set in /etc/security/pwhistory.conf OR on the module
# line in common-password, but not both (5.3.3.3.x).
pam_conf_or_arg() {
    local id=$CUR_ID mod=${P[module]-} key=${P[key]-} op=${P[op]-flag} exp=${P[value]-} conf=${P[conf]-}
    local cv="" av="" l cfound=0 afound=0 f=$R$conf line
    local -a ev=()
    if [[ -r $f ]]; then
        while IFS= read -r line; do
            [[ $line =~ ^[[:space:]]*# ]] && continue
            if [[ $op == flag ]]; then
                [[ $line =~ ^[[:space:]]*$key[[:space:]]*(#.*)?$ ]] && { cfound=1; cv=set; }
            elif [[ $line =~ ^[[:space:]]*$key[[:space:]]*=[[:space:]]*([^[:space:]#]+) ]]; then
                cfound=1; cv=${BASH_REMATCH[1]}
            fi
        done <"$f"
    fi
    if pam_lines common-password "$mod"; then
        for l in "${PAM_LINES[@]}"; do
            [[ $l =~ ^[[:space:]]*password[[:space:]] ]] || continue
            pam_args_of "$l" "$mod"
            if [[ $op == flag ]]; then
                has_arg "$REPLY" "$key" && { afound=1; av=set; }
            elif arg_value "$REPLY" "$key"; then
                afound=1; av=$REPLY
            fi
        done
    fi
    (( cfound )) && ev+=("$conf: $key${cv:+ = $cv}")
    (( afound )) && ev+=("/etc/pam.d/common-password ($mod): $key${av:+=$av}")
    if (( cfound && afound )); then
        result "$id" FAIL "${ev[@]}" "$key is configured in both $conf and the PAM stack; use only one method"
        return
    fi
    if (( ! cfound && ! afound )); then
        result "$id" FAIL "$key is set neither in $conf nor on the $mod line in /etc/pam.d/common-password"
        return
    fi
    local val=$cv
    (( afound )) && val=$av
    if [[ $op == flag ]] || val_ok "$op" "$exp" "$val"; then
        result "$id" PASS "${ev[@]}" "expected ${op/#flag/option present} ${exp:+$op $exp}"
    else
        result "$id" FAIL "${ev[@]}" "expected $key $op $exp"
    fi
}

# ------------------------------------------------------------ conf_kv ------
# Effective value of key from an ordered list of plain "key = value" files.
# kv_collect <key> <files...> -> KV_VALUE KV_FILE KV_ALL KV_FOUND
kv_collect() {
    local key=$1 f line
    shift
    KV_VALUE="" KV_FILE="" KV_ALL="" KV_FOUND=0
    for f in "$@"; do
        [[ -r $R$f ]] || continue
        while IFS= read -r line; do
            [[ $line =~ ^[[:space:]]*# ]] && continue
            if [[ $line =~ ^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*([^[:space:]#]+) ]]; then
                if [[ ${BASH_REMATCH[1],,} == "${key,,}" ]]; then
                    KV_VALUE=${BASH_REMATCH[2]} KV_FILE=$f KV_FOUND=1
                    KV_ALL+="$f: $key=$KV_VALUE; "
                fi
            elif [[ $line =~ ^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*$ && ${BASH_REMATCH[1],,} == "${key,,}" ]]; then
                KV_VALUE=set KV_FILE=$f KV_FOUND=1
                KV_ALL+="$f: $key; "
            fi
        done <"$R$f"
    done
}

# conf file list with globs, in precedence order (later wins)
conf_files() {
    local spec=$1 e
    CONF_FILES=()
    local -a ents
    IFS=',' read -ra ents <<<"$spec"
    for e in "${ents[@]}"; do
        expand_glob "$e"
        if [[ $e == *[*?[]* ]]; then
            local -a sorted
            mapfile -t sorted < <(printf '%s\n' "${GLOB[@]}" | LC_ALL=C sort)
            CONF_FILES+=("${sorted[@]}")
        else
            CONF_FILES+=("$e")
        fi
    done
}

chk_conf_kv() {
    local id=$1 key=${P[key]-} op=${P[op]-} exp=${P[value]-} absent=${P[absent]:-fail} v="" where="" bad=0
    local -a ev=()
    case ${P[src]-} in
        catcfg:*)
            if ! catcfg_get "${P[src]#catcfg:}" "${P[section]-}" "$key"; then
                result "$id" ERROR "cannot read effective configuration of ${P[src]#catcfg:}: ${NEED_ERR}"
                return
            fi
            if [[ -n ${P[altkey]-} ]]; then
                # NTP / FallbackNTP style: any of the keys set
                local k
                local -a ks
                IFS=',' read -ra ks <<<"${P[altkey]-}"
                local got=""
                for k in "${ks[@]}"; do
                    catcfg_get "${P[src]#catcfg:}" "${P[section]-}" "$k" || continue
                    if [[ -n $CC_VALUE ]]; then
                        ev+=("$k=$CC_VALUE (in $CC_FILE)")
                        got=1
                    else
                        ev+=("$k is not set")
                    fi
                done
                if [[ -n $got ]]; then
                    result "$id" PASS "${ev[@]}" "verify the configured servers against site policy"
                else
                    result "$id" FAIL "${ev[@]}" "expected at least one of ${P[altkey]//,/, } to be set to an approved time server"
                fi
                return
            fi
            v=$CC_VALUE where=$CC_FILE
            if [[ -z $v ]]; then
                if [[ $absent == default && -n $CC_DEFAULT ]]; then
                    v=$CC_DEFAULT where="built-in default, not set explicitly"
                fi
            fi
            ;;
        files:*)
            conf_files "${P[src]#files:}"
            kv_collect "$key" "${CONF_FILES[@]}"
            v=$KV_VALUE where=$KV_FILE
            [[ -n $KV_ALL ]] && ev+=("assignments (last wins): ${KV_ALL%; }")
            ;;
    esac
    if [[ -z $v ]]; then
        case $absent in
            pass) ev+=("$key is not set; the module default is compliant") ;;
            *)
                if [[ $op == flag ]]; then
                    ev+=("!$key is not set, expected it to be present")
                else
                    op_text "$op" "$exp"; ev+=("!$key is not set, expected $REPLY")
                fi
                bad=1 ;;
        esac
    else
        if [[ $op == flag ]]; then
            ev+=("$key is set (in $where)")
        elif val_ok "$op" "$exp" "$v"; then
            op_text "$op" "$exp"; ev+=("$key=$v ($where), expected $REPLY")
        else
            op_text "$op" "$exp"; ev+=("!$key=$v ($where), expected $REPLY")
            bad=1
        fi
    fi
    # arguments on the PAM module line override the configuration file
    if [[ -n ${P[pam_file]-} ]] && pam_lines "${P[pam_file]-}" "${P[pam_mod]-}"; then
        local l a pv
        for l in "${PAM_LINES[@]}"; do
            [[ $l =~ ^[[:space:]]*${P[pam_type]:-password}[[:space:]]+(requisite|required|sufficient)[[:space:]] ]] || continue
            pam_args_of "$l" "${P[pam_mod]-}"
            a=$REPLY
            if [[ $op == flag ]]; then
                has_arg "$a" "$key" && ev+=("/etc/pam.d/${P[pam_file]-}: module argument $key is also present")
            elif arg_value "$a" "$key"; then
                pv=$REPLY
                if val_ok "$op" "$exp" "$pv"; then
                    ev+=("/etc/pam.d/${P[pam_file]-}: module argument $key=$pv overrides the file and is compliant")
                else
                    op_text "$op" "$exp"; ev+=("!/etc/pam.d/${P[pam_file]-}: module argument $key=$pv overrides the file, expected $REPLY")
                    bad=1
                fi
            fi
        done
    fi
    # 6.1.1.1.3 also needs both services loaded and active
    if [[ -n ${P[units_active]-} ]]; then
        need units || return
        local u
        local -a us
        IFS=',' read -ra us <<<"${P[units_active]-}"
        for u in "${us[@]}"; do
            if unit_is_active "$u"; then ev+=("$u is active"); else ev+=("!$u is not active"); bad=1; fi
        done
    fi
    result "$id" "$( (( bad )) && echo FAIL || echo PASS)" "${ev[@]}"
}
