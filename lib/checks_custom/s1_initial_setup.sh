#!/usr/bin/env bash
# lib/checks_custom/s1_initial_setup.sh - custom checks, benchmark section 1.
# Each function names the benchmark ID it ports and which Audit steps it implements.
# Checks read facts and files only (through $R and the fact accessors).
# shellcheck disable=SC2034,SC2154

# 1.2.1.3 Ensure access to gpg key files are configured.
# Step 1: gpg files in /usr/share/keyrings and /etc/apt/trusted.gpg.d must be 0644 or
# stricter and root:root (fact apt_keyfiles lists the offenders found by the PDF's find).
# Step 2: key files named by Signed-By outside those dirs must be 0644 or stricter, root:root.
cus_1_2_1_3() {
    local id=$1 m u g p f key
    local -a bad=() ok=() keys=() PERM_OK=() PERM_BAD=()
    _need_fact apt_keyfiles || { result "$id" ERROR "fact apt_keyfiles unavailable: $NEED_ERR"; return; }
    while IFS=$'\t' read -r m u g p; do
        mode4 "$m"
        [[ -n $p ]] && bad+=("$p: mode $M4 owner $u group $g; expected 0644 or stricter and root:root")
    done <"$FACT_FILE"
    [[ ${#bad[@]} -eq 0 ]] && ok+=("step 1: all *gpg files in /usr/share/keyrings and /etc/apt/trusted.gpg.d are 0644 or stricter, root:root")
    shopt -s nullglob
    for f in "$R/etc/apt/sources.list" "$R"/etc/apt/sources.list.d/*.list "$R"/etc/apt/sources.list.d/*.sources; do
        [[ -r $f ]] || continue
        while IFS= read -r key; do
            keys+=("$key")
        done < <(grep -Pho -- '\bSigned-By\b\s*[=:]\s*\K\S+' "$f" 2>/dev/null)
    done
    shopt -u nullglob
    if (( ${#keys[@]} )); then
        local -a uniq
        mapfile -t uniq < <(printf '%s\n' "${keys[@]}" | LC_ALL=C sort -u)
        for key in "${uniq[@]}"; do
            key=${key//\"/}
            key=${key%,}
            [[ $key == /* ]] || continue
            case $key in /usr/share/keyrings/*|/etc/apt/trusted.gpg.d/*) continue ;; esac
            perm_eval "$key" 644 root root || true
        done
        bad+=("${PERM_BAD[@]}")
        ok+=("${PERM_OK[@]}")
    fi
    (( ${#keys[@]} )) || ok+=("step 2: no Signed-By key files outside the standard keyring directories")
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# 1.2.1.10 Ensure repositories are set to https in /etc/apt/sources.list.
# The PDF greps '^\s*deb\s+http://'. This port also catches deb-src and an options
# bracket in front of the URI (deb [signed-by=...] http://...).
cus_1_2_1_10() {
    local id=$1 f=$R/etc/apt/sources.list hits
    if [[ ! -r $f ]]; then
        result "$id" PASS "/etc/apt/sources.list does not exist; nothing to check"
        return
    fi
    hits=$(grep -Pin -- '^\s*deb(-src)?\s+(\[[^]]*\]\s+)?http://' "$f")
    if [[ -n $hits ]]; then
        result "$id" FAIL "plain http repository in /etc/apt/sources.list (line: entry), expected https:" "${hits//$'\n'/$'\n'}"
    else
        result "$id" PASS "/etc/apt/sources.list: no deb/deb-src entry uses plain http://"
    fi
}

# 1.2.1.11 Ensure repositories are set to https in /etc/apt/sources.list.d directory.
# Step 1: *.list files (as 1.2.1.10). Step 2: deb822 *.sources files, URIs: field.
cus_1_2_1_11() {
    local id=$1 f line n tok
    local -a bad=() checked=()
    shopt -s nullglob
    for f in "$R"/etc/apt/sources.list.d/*.list; do
        checked+=("${f#"$R"}")
        while IFS= read -r line; do
            bad+=("${f#"$R"}:$line")
        done < <(grep -Pin -- '^\s*deb(-src)?\s+(\[[^]]*\]\s+)?http://' "$f")
    done
    for f in "$R"/etc/apt/sources.list.d/*.sources; do
        checked+=("${f#"$R"}")
        n=0
        local inuris=0
        while IFS= read -r line || [[ -n $line ]]; do
            n=$((n + 1))
            if [[ $line =~ ^[[:space:]]*# ]]; then continue; fi
            if [[ $line =~ ^[Uu][Rr][Ii][Ss]:[[:space:]]*(.*)$ ]]; then
                inuris=1
                line=${BASH_REMATCH[1]}
            elif [[ $inuris == 1 && $line =~ ^[[:space:]]+(.*)$ ]]; then
                line=${BASH_REMATCH[1]}
            else
                inuris=0
                continue
            fi
            for tok in $line; do
                [[ ${tok,,} == http://* ]] && bad+=("${f#"$R"}:$n:URIs: $tok")
            done
        done <"$f"
    done
    shopt -u nullglob
    if (( ${#bad[@]} )); then
        result "$id" FAIL "plain http repositories, expected https:" "${bad[@]}"
    elif (( ${#checked[@]} )); then
        result "$id" PASS "no plain http:// repository in: ${checked[*]}"
    else
        result "$id" PASS "no repository files in /etc/apt/sources.list.d"
    fi
}

# 1.3.1.2 Ensure AppArmor is enabled.
# Not disabled on the kernel command line (grub.cfg linux lines,
# /etc/default/grub.d/apparmor.cfg; the running /proc/cmdline is checked too),
# apparmor.service enabled and active, and at least one profile loaded.
cus_1_3_1_2() {
    local id=$1 n
    local -a bad=() ok=()
    need units || return
    if grep -Pqs -- '^\s*linux.*\bapparmor=0\b' "$R/boot/grub/grub.cfg"; then
        bad+=("/boot/grub/grub.cfg: a linux line contains apparmor=0")
    else
        ok+=("/boot/grub/grub.cfg: no linux line contains apparmor=0")
    fi
    if grep -Pqs -- 'apparmor=0' "$R/etc/default/grub.d/apparmor.cfg"; then
        bad+=("/etc/default/grub.d/apparmor.cfg: contains apparmor=0")
    fi
    if grep -Pqs -- '\bapparmor=0\b' "$R/proc/cmdline"; then
        bad+=("/proc/cmdline: the running kernel was booted with apparmor=0")
    fi
    unit_describe apparmor.service
    if unit_is_enabled apparmor.service && unit_is_active apparmor.service; then
        ok+=("apparmor.service: $REPLY (enabled/active)")
    else
        bad+=("apparmor.service: $REPLY (enabled-state/active-state), expected enabled and active")
    fi
    if _need_fact aa_status; then
        n=$(grep -Po -- '^\s*\K[0-9]+(?=\s+profiles are loaded)' "$FACT_FILE" | head -n1)
        if [[ -n $n ]] && (( n > 0 )); then
            ok+=("$n AppArmor profiles are loaded")
        else
            bad+=("no AppArmor profiles are loaded (apparmor_status reports ${n:-nothing})")
        fi
    else
        bad+=("apparmor_status is not available, cannot confirm loaded profiles")
    fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# 1.4.1 Ensure bootloader password is set.
# grub.cfg needs 'set superusers=' and a 'password_pbkdf2 <user> grub.pbkdf2.sha512...' line.
cus_1_4_1() {
    local id=$1 su pw
    local f=$R/boot/grub/grub.cfg
    if [[ ! -r $f ]]; then
        result "$id" FAIL "/boot/grub/grub.cfg does not exist or is not readable; expected 'set superusers' and a password_pbkdf2 entry"
        return
    fi
    su=$(grep -P -- '^\s*set superusers=' "$f" | head -n1)
    pw=$(grep -P -- '^\s*password_pbkdf2\s+\S+\s+grub\.pbkdf2\.sha512\.' "$f" | awk '{print $1" "$2" "substr($3,1,20)"..."}' | head -n1)
    local -a bad=() ok=()
    [[ -n $su ]] && ok+=("grub.cfg: $su") || bad+=("grub.cfg: no 'set superusers=\"<username>\"' line")
    [[ -n $pw ]] && ok+=("grub.cfg: $pw (hash shortened)") || bad+=("grub.cfg: no 'password_pbkdf2 <username> grub.pbkdf2.sha512...' line")
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# 1.5.7 Ensure Automatic Error Reporting is configured.
# If apport is installed, /etc/default/apport must not have enabled=<non-0>, and
# apport.service must not be active.
cus_1_5_7() {
    local id=$1 hit
    local -a bad=() ok=()
    need dpkg units || return
    if pkg_installed apport; then
        hit=$(grep -Psi -- '^\s*enabled\s*=\s*[^0]\b' "$R/etc/default/apport" 2>/dev/null)
        if [[ -n $hit ]]; then
            bad+=("/etc/default/apport: $hit, expected enabled=0")
        else
            ok+=("/etc/default/apport: enabled is not set to a non-0 value")
        fi
    else
        ok+=("apport is not installed")
    fi
    if unit_is_active apport.service; then
        bad+=("apport.service is active, expected not active")
    else
        ok+=("apport.service is not active")
    fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# 1.5.10 Ensure core file size is configured.
# A '* hard core' limit in limits.conf / limits.d must exist and none may be above 0.
cus_1_5_10() {
    local id=$1 f line val
    local -a files=() hits=() bad=()
    [[ -r $R/etc/security/limits.conf ]] && files+=("/etc/security/limits.conf")
    shopt -s nullglob
    local d
    mapfile -t d < <(printf '%s\n' "$R"/etc/security/limits.d/*.conf | LC_ALL=C sort)
    shopt -u nullglob
    for f in "${d[@]}"; do [[ -n $f ]] && files+=("${f#"$R"}"); done
    local last=""
    for f in "${files[@]}"; do
        while IFS= read -r line; do
            hits+=("$f: $line")
            if [[ $line =~ hard[[:space:]]+core[[:space:]]+([^[:space:]#]+) ]]; then
                val=${BASH_REMATCH[1]}
                last=$val
                if ! is_uint "$val" || (( val > 0 )); then bad+=("$f: '* hard core $val', expected 0"); fi
            fi
        done < <(grep -Psi -- '^\s*\*\s+hard\s+core\b' "$R$f")
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${hits[@]}"
    elif (( ${#hits[@]} == 0 )); then
        result "$id" FAIL "no '* hard core 0' line in /etc/security/limits.conf or /etc/security/limits.d/*.conf"
    else
        result "$id" PASS "${hits[@]}" "effective value (last line wins): hard core $last"
    fi
}

# --- banners (1.6.1 - 1.6.4) ---------------------------------------------------
# banner_scan <files...>: BAN_HITS = lines with \m \r \s \v or the OS name
banner_scan() {
    local f hits
    BAN_HITS=() BAN_SEEN=()
    banner_re
    for f in "$@"; do
        [[ -r $R$f && -f $R$f ]] || continue
        BAN_SEEN+=("$f")
        hits=$(grep -Pni -- "$BANNER_RE" "$R$f" | head -n 3)
        [[ -n $hits ]] && BAN_HITS+=("$f: ${hits//$'\n'/ | }")
    done
}

# glob helper that returns unprefixed paths in GLOB (existing, sorted)
glob_files() {
    local p f
    GLOB=()
    shopt -s nullglob
    for p in "$@"; do
        for f in $R$p; do GLOB+=("${f#"$R"}"); done
    done
    shopt -u nullglob
}

# 1.6.1 Ensure /etc/motd is configured: no \m \r \s \v and no OS name in /etc/motd, /etc/motd.d/*.
cus_1_6_1() {
    local id=$1
    glob_files '/etc/motd' '/etc/motd.d/*'
    banner_scan "${GLOB[@]}"
    if (( ${#BAN_HITS[@]} )); then
        result "$id" FAIL "OS information or escape codes (\\m \\r \\s \\v, OS name) found:" "${BAN_HITS[@]}"
    elif (( ${#BAN_SEEN[@]} )); then
        result "$id" PASS "no OS information in: ${BAN_SEEN[*]}; review the text against site policy"
    else
        result "$id" PASS "no motd files exist (a message of the day is optional)"
    fi
}

# banner_site_check <file>: optional exact match against BANNER_FILE from site.conf
banner_site_check() {
    SITE_BAN_MSG="" SITE_BAN_BAD=0
    local sf=${SITE[BANNER_FILE]-}
    [[ -n $sf ]] || return 0
    if [[ ! -r $R$sf ]]; then
        SITE_BAN_MSG="BANNER_FILE $sf from site.conf is not readable"
        SITE_BAN_BAD=1
    elif [[ -r $R$1 ]] && cmp -s -- "$R$1" "$R$sf"; then
        SITE_BAN_MSG="$1 matches the site banner $sf"
    else
        SITE_BAN_MSG="$1 differs from the site banner $sf"
        SITE_BAN_BAD=1
    fi
}

# 1.6.2 Ensure /etc/issue is configured: /etc/issue and issue.d fragments carry no OS information.
cus_1_6_2() {
    local id=$1
    glob_files '/etc/issue' '/usr/lib/issue.d/*' '/etc/issue.d/*' '/run/issue.d/*'
    banner_scan "${GLOB[@]}"
    banner_site_check /etc/issue
    if (( ${#BAN_HITS[@]} )); then
        result "$id" FAIL "OS information or escape codes (\\m \\r \\s \\v, OS name) found:" "${BAN_HITS[@]}"
    elif (( SITE_BAN_BAD )); then
        result "$id" FAIL "$SITE_BAN_MSG"
    else
        result "$id" PASS "no OS information in: ${BAN_SEEN[*]:-no issue files}" ${SITE_BAN_MSG:+"$SITE_BAN_MSG"}
    fi
}

# 1.6.3 Ensure /etc/issue.net is configured: no OS information (the file may be absent).
cus_1_6_3() {
    local id=$1
    banner_scan /etc/issue.net
    banner_site_check /etc/issue.net
    if (( ${#BAN_HITS[@]} )); then
        result "$id" FAIL "OS information or escape codes (\\m \\r \\s \\v, OS name) found:" "${BAN_HITS[@]}"
    elif (( SITE_BAN_BAD )); then
        result "$id" FAIL "$SITE_BAN_MSG"
    elif (( ${#BAN_SEEN[@]} )); then
        result "$id" PASS "/etc/issue.net has no OS information; review the text against site policy" ${SITE_BAN_MSG:+"$SITE_BAN_MSG"}
    else
        result "$id" PASS "/etc/issue.net does not exist (the benchmark notes it may be absent; creating it with the site banner is recommended)"
    fi
}

# 1.6.4 Ensure pam_motd is configured: for sshd, login, su and gdm-password, a
# pam_motd.so session line with motd=<file> must not point at a file that holds
# OS information (the PDF script's test).
cus_1_6_4() {
    local id=$1 svc file line mp
    local -a bad=() ok=()
    banner_re
    for svc in sshd login su gdm-password; do
        if [[ -f $R/etc/pam.d/$svc ]]; then file=/etc/pam.d/$svc
        elif [[ -f $R/usr/lib/pam.d/$svc ]]; then file=/usr/lib/pam.d/$svc
        else continue; fi
        while IFS= read -r line; do
            while IFS= read -r mp; do
                mp=${mp#\"}; mp=${mp%\"}; mp=${mp#\'}; mp=${mp%\'}
                [[ -r $R$mp ]] || continue
                if grep -Pqi -- "$BANNER_RE" "$R$mp"; then
                    bad+=("$file: $line -> $mp contains OS information or escape codes")
                else
                    ok+=("$file: motd=$mp has no OS information")
                fi
            done < <(grep -oP '\bmotd=\K"[^"]+"|\bmotd=\K'\''[^'\'']+'\''|\bmotd=\K\S+' <<<"$line")
        done < <(grep -Pi -- '^\s*session\s+(required|optional)\s+pam_motd\.so\b.*\bmotd=' "$R$file" 2>/dev/null)
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]:-no pam_motd.so line with an explicit motd= argument found in sshd, login, su or gdm-password}"
    fi
}

# --- manual evidence ----------------------------------------------------------
man_ev_1_1_1_11() {
    if need_mounts && need_lsmod && need_modprobe && need_kmod; then
        local m="" t
        for t in "${MNT_TARGETS[@]}"; do m+="${MNT_FSTYPE[$t]} "; done
        printf 'filesystem types currently mounted: %s\n' "$(tr ' ' '\n' <<<"$m" | LC_ALL=C sort -u | tr '\n' ' ')"
        local mod n cnt=0 unprotected=""
        while IFS= read -r mod; do
            n=$(basename -- "$mod"); n=${n%%.*}; n=${n//-/_}
            [[ ${LSMOD[$n]+x} ]] && printf 'loaded filesystem module: %s\n' "$n"
            if [[ -z ${MOD_BLACKLIST[$n]+x} || -z ${MOD_INSTALL[$n]+x} ]]; then
                cnt=$((cnt + 1))
                (( cnt <= 15 )) && unprotected+="$n "
            fi
        done < <(grep -- '/kernel/fs/' "$FACTS_DIR/kmod_files" | grep -v '/kernel/fs/nls/' | LC_ALL=C sort -u)
        printf 'filesystem modules without both blacklist and install override: %s%s\n' "$cnt" "${unprotected:+ (first: ${unprotected% })}"
    else
        printf 'could not collect module facts\n'
    fi
}

man_ev_1_2_1_1() {
    local f hits
    shopt -s nullglob
    for f in "$R/etc/apt/sources.list" "$R"/etc/apt/sources.list.d/*.list; do
        [[ -r $f ]] || continue
        hits=$(grep -Pn -- '^\s*(deb(-src)?)\s+(\[(?![^\]]*\bSigned-By\b)[^\]]*\]|[^\[])' "$f" | head -n 5)
        [[ -n $hits ]] && printf '%s: entry without Signed-By: %s\n' "${f#"$R"}" "${hits//$'\n'/ | }"
    done
    for f in "$R"/etc/apt/sources.list.d/*.sources; do
        awk -v F="${f#"$R"}" 'function flush(){ if (u && !s) print F ": stanza ending near line " ln " has URIs but no Signed-By"; u=0; s=0 }
            /^[[:blank:]]*$/ { flush() } /^[[:blank:]]*URIs:[[:blank:]]*[^[:blank:]]/ { u=1 }
            /^[[:blank:]]*Signed-By:[[:blank:]]*[^[:blank:]]/ { s=1 } { ln=NR } END { flush() }' "$f"
    done
    shopt -u nullglob
}

man_ev_1_2_2_1() {
    [[ -e $R/var/run/reboot-required || -e $R/run/reboot-required ]] && printf 'a reboot is required (reboot-required exists)\n'
    printf 'pending updates are not checked: that needs apt update (network)\n'
}
