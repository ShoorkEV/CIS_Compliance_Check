#!/usr/bin/env bash
# lib/checks_custom/s5_access.sh - custom checks, benchmark section 5
# (sudo, su, account policy, root and system accounts, shell environment).
# shellcheck disable=SC2034,SC2154

# ---- shared helpers (also used by section 7) -------------------------------
# cap_lines <max> <lines...>: sets CAPPED to the first <max> lines plus a count
cap_lines() {
    local max=$1
    shift
    CAPPED=("${@:1:max}")
    (( $# > max )) && CAPPED+=("... and $(($# - max)) more")
    return 0
}

ACCT_LOADED=0
declare -A VALID_SHELL=()
acct_load() {
    (( ACCT_LOADED )) && return 0
    PASSWD_L=() SHADOW_L=() GROUP_L=() ACCT_SHADOW_OK=0
    [[ -r $R/etc/passwd ]] || { NEED_ERR="/etc/passwd is not readable"; return 1; }
    [[ -r $R/etc/group ]] || { NEED_ERR="/etc/group is not readable"; return 1; }
    mapfile -t PASSWD_L <"$R/etc/passwd"
    mapfile -t GROUP_L <"$R/etc/group"
    if [[ -r $R/etc/shadow ]]; then
        mapfile -t SHADOW_L <"$R/etc/shadow"
        ACCT_SHADOW_OK=1
    fi
    VALID_SHELL=()
    local s
    if [[ -r $R/etc/shells ]]; then
        while IFS= read -r s; do
            [[ $s == /* && ${s##*/} != nologin ]] && VALID_SHELL[$s]=1
        done <"$R/etc/shells"
    fi
    ACCT_LOADED=1
}
need_acct() { acct_load; }
need_shadow() { acct_load || return 1; (( ACCT_SHADOW_OK )) || { NEED_ERR="/etc/shadow is not readable"; return 1; }; }

# login_defs_get <KEY> -> REPLY (last uncommented value), rc 1 when absent
login_defs_get() {
    local v
    v=$(grep -Pio -- "^\s*$1\s+\K\S+" "$R/etc/login.defs" 2>/dev/null | tail -n1)
    REPLY=$v
    [[ -n $v ]]
}

# ---- sudoers ----------------------------------------------------------------
SUDO_EFF=() SUDO_ALL=()
# sudoers_collect: SUDO_EFF = files sudo reads (follows include/includedir);
# SUDO_ALL = those plus every file in /etc/sudoers.d (the PDF greps the directory).
sudoers_collect() {
    SUDO_EFF=() SUDO_ALL=()
    local -A seen=()
    sudoers_walk /etc/sudoers 0
    local f
    SUDO_ALL=("${SUDO_EFF[@]}")
    shopt -s nullglob
    for f in "$R"/etc/sudoers.d/*; do
        f=${f#"$R"}
        [[ -f $R$f ]] || continue
        [[ -n ${seen[$f]+x} ]] || SUDO_ALL+=("$f")
    done
    shopt -u nullglob
}
sudoers_walk() { # sudoers_walk <file> <depth>
    local f=$1 depth=$2 line inc d g
    [[ -r $R$f && -f $R$f ]] || return 0
    for g in "${SUDO_EFF[@]}"; do [[ $g == "$f" ]] && return 0; done
    SUDO_EFF+=("$f")
    (( depth >= 10 )) && return 0
    while IFS= read -r line; do
        if [[ $line =~ ^[[:space:]]*[#@]include[[:space:]]+\"?([^[:space:]\"]+) ]]; then
            inc=${BASH_REMATCH[1]}
            [[ $inc == /* ]] || inc=/etc/$inc
            sudoers_walk "$inc" $((depth + 1))
        elif [[ $line =~ ^[[:space:]]*[#@]includedir[[:space:]]+\"?([^[:space:]\"]+) ]]; then
            d=${BASH_REMATCH[1]}
            [[ $d == /* ]] || d=/etc/$d
            shopt -s nullglob
            local ff
            for ff in "$R$d"/*; do
                ff=${ff#"$R"}
                [[ ${ff##*/} == *.* || ${ff##*/} == *~ ]] && continue
                sudoers_walk "$ff" $((depth + 1))
            done
            shopt -u nullglob
        fi
    done <"$R$f"
}
# sudo_grep <perl-regex> <files...>: prints "file: line" for each match
sudo_grep() {
    local rx=$1 f line
    shift
    for f in "$@"; do
        while IFS= read -r line; do
            printf '%s: %s\n' "$f" "$line"
        done < <(grep -Pi -- "$rx" "$R$f" 2>/dev/null)
    done
}

# 5.2.2 Ensure sudo commands use pty: no '!use_pty' anywhere in sudoers or sudoers.d,
# and an explicit 'Defaults use_pty' in a file sudo reads. sudo-rs enables use_pty by
# default, but the benchmark still requires the explicit setting.
cus_5_2_2() {
    local id=$1
    local -a neg pos
    sudoers_collect
    mapfile -t neg < <(sudo_grep '^\s*Defaults\s+([^#\n\r]+,\s*)?!use_pty\b' "${SUDO_ALL[@]}")
    mapfile -t pos < <(sudo_grep '^\s*Defaults\s+([^#\n\r]+,\s*)?use_pty\b' "${SUDO_EFF[@]}")
    if (( ${#neg[@]} )); then
        result "$id" FAIL "use_pty is disabled with !use_pty:" "${neg[@]}"
    elif (( ${#pos[@]} == 0 )); then
        result "$id" FAIL "no explicit 'Defaults use_pty' in ${SUDO_EFF[*]:-/etc/sudoers}, expected at least one (also required on sudo-rs)"
    else
        result "$id" PASS "use_pty is set explicitly:" "${pos[@]}"
    fi
}

# 5.2.3 Ensure sudo log file exists.
# Pass: Method A (sudo events reach syslog/journald) on any system, or Method B
# (Defaults logfile=) on classic sudo. This audit never runs sudo to create a test
# event, so Method A looks for existing sudo / sudo-rs entries in the journal and in
# /var/log/auth.log.
cus_5_2_3() {
    local id=$1 impl a b
    local -a logf=() ev=()
    need dpkg || return
    if pkg_installed sudo-rs; then impl=sudo-rs
    elif pkg_installed sudo; then impl="classic sudo"
    else
        result "$id" FAIL "neither sudo-rs nor sudo is installed"
        return
    fi
    ev+=("implementation: $impl")
    sudoers_collect
    if [[ $impl == "classic sudo" ]]; then
        mapfile -t logf < <(sudo_grep '^\s*Defaults\s+([^#]+,\s*)?logfile\s*=\s*("|'\'')?\S+("|'\'')?(,\s*\S+\s*)*\s*(#.*)?$' "${SUDO_ALL[@]}")
        if (( ${#logf[@]} )); then
            result "$id" PASS "Method B: logfile is set:" "${logf[@]}" "${ev[@]}"
            return
        fi
        ev+=("Method B: no 'Defaults logfile=' line in sudoers")
    else
        ev+=("Method B does not apply: sudo-rs ignores or rejects the logfile option")
    fi
    a=0
    if fact sudo_log && grep -Pq -- '\b(sudo|sudo-rs)\[[0-9]+\]|\bsudo(-rs)?:' "$FACT_FILE"; then
        a=1
        ev+=("Method A: sudo events found in the journal ($(grep -c . "$FACT_FILE") recent lines)")
    fi
    if grep -Pqs -- '\b(sudo|sudo-rs)\[[0-9]+\]:' "$R/var/log/auth.log"; then
        a=1
        ev+=("Method A: sudo events found in /var/log/auth.log")
    fi
    if (( a )); then
        result "$id" PASS "${ev[@]}" "the audit does not generate a test event; existing entries were used"
    else
        result "$id" FAIL "no evidence that sudo events are logged: no journal or auth.log entries from sudo / sudo-rs and no logfile setting" \
            "${ev[@]}" "if sudo has not been used yet, run 'sudo true' once and audit again"
    fi
}

# 5.2.5 Ensure re-authentication for privilege escalation is not disabled globally:
# no uncommented '!authenticate' in sudoers or sudoers.d.
cus_5_2_5() {
    local id=$1
    local -a hits
    sudoers_collect
    mapfile -t hits < <(sudo_grep '^\s*[^#\s].*!authenticate\b' "${SUDO_ALL[@]}")
    if (( ${#hits[@]} )); then
        result "$id" FAIL "re-authentication is disabled with !authenticate:" "${hits[@]}"
    else
        result "$id" PASS "no uncommented '!authenticate' in ${SUDO_ALL[*]}"
    fi
}

# 5.2.6 Ensure sudo timestamp_timeout is configured: explicitly set, never negative
# and never above 15 minutes.
cus_5_2_6() {
    local id=$1 line v f
    local -a bad=() ok=() hits
    sudoers_collect
    for f in "${SUDO_ALL[@]}"; do
        while IFS= read -r line; do
            v=$(grep -Po -- 'timestamp_timeout\s*=\s*\K-?[0-9]+' <<<"$line" | head -n1)
            if [[ -z $v ]]; then continue; fi
            if (( v < 0 )); then
                bad+=("$f: timestamp_timeout=$v is negative (disables the timeout)")
            elif (( v > 15 )); then
                bad+=("$f: timestamp_timeout=$v exceeds 15 minutes")
            else
                ok+=("$f: timestamp_timeout=$v")
            fi
        done < <(grep -Psi -- '^\s*Defaults\s+([^#\n\r]+,\s*)?timestamp_timeout\s*=\s*[-0-9]+' "$R$f" 2>/dev/null)
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    elif (( ${#ok[@]} == 0 )); then
        result "$id" FAIL "timestamp_timeout is not explicitly configured in sudoers, expected a value from 0 to 15"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# 5.2.7 Ensure access to the su command is restricted: /etc/pam.d/su has
# 'auth required|requisite pam_wheel.so' with use_uid and group=<name>, and the
# named group has no members.
cus_5_2_7() {
    local id=$1 line grp members gl
    line=$(grep -Pi -- '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)(?=.*\bgroup=\S+).*' "$R/etc/pam.d/su" 2>/dev/null | head -n1)
    if [[ -z $line ]]; then
        result "$id" FAIL "/etc/pam.d/su has no 'auth required pam_wheel.so use_uid group=<name>' line (required or requisite, with use_uid and group=)"
        return
    fi
    grp=$(grep -Po -- '\bgroup=\K\S+' <<<"$line" | head -n1)
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    gl=""
    local g
    for g in "${GROUP_L[@]}"; do
        [[ $g == "$grp":* ]] && { gl=$g; break; }
    done
    if [[ -z $gl ]]; then
        result "$id" FAIL "pam_wheel names group '$grp', which does not exist in /etc/group" "/etc/pam.d/su: $line"
        return
    fi
    members=${gl##*:}
    if [[ -n $members ]]; then
        result "$id" FAIL "group $grp has members ($members), expected an empty member list" "/etc/pam.d/su: $line"
    else
        result "$id" PASS "/etc/pam.d/su: $line" "group $grp exists and has no members"
    fi
}

# ---- 5.4.1 password policy --------------------------------------------------
# shadow_hash_users: prints "name:f3:f4:f5:f6:f7" for accounts whose password field
# is a hash ($...$), the PDF's ($2~/^\$.+\$/) test.
shadow_hash_rows() {
    local l name pw f3 f4 f5 f6 f7
    for l in "${SHADOW_L[@]}"; do
        IFS=: read -r name pw f3 f4 f5 f6 f7 _ <<<"$l"
        [[ $pw =~ ^\$.+\$ ]] || continue
        printf '%s:%s:%s:%s:%s:%s\n' "$name" "$f3" "$f4" "$f5" "$f6" "$f7"
    done
}

# 5.4.1.1 Ensure password expiration is configured: PASS_MAX_DAYS 1..365 in
# /etc/login.defs and for every account with a password hash.
cus_5_4_1_1() {
    local id=$1 max v name f3 f4 f5
    local -a bad=() ok=()
    need shadow || return
    site_val PASS_MAX_DAYS 365; max=$REPLY
    if login_defs_get PASS_MAX_DAYS && is_uint "$REPLY" && (( REPLY >= 1 && REPLY <= max )); then
        ok+=("/etc/login.defs: PASS_MAX_DAYS $REPLY (expected 1 to $max)")
    else
        bad+=("/etc/login.defs: PASS_MAX_DAYS ${REPLY:-not set}, expected 1 to $max")
    fi
    while IFS=: read -r name f3 f4 f5 _; do
        if ! is_uint "$f5" || (( f5 < 1 || f5 > max )); then
            bad+=("user $name: PASS_MAX_DAYS '${f5:-empty}' in /etc/shadow, expected 1 to $max")
        fi
    done < <(shadow_hash_rows)
    (( ${#bad[@]} )) || ok+=("every account with a password has a maximum password age of 1 to $max days")
    cap_lines 25 "${bad[@]}"
    if (( ${#bad[@]} )); then result "$id" FAIL "${CAPPED[@]}" "${ok[@]}"; else result "$id" PASS "${ok[@]}"; fi
}

# 5.4.1.3 Ensure password expiration warning days is configured: PASS_WARN_AGE >= 7.
cus_5_4_1_3() {
    local id=$1 min name f3 f4 f5 f6
    local -a bad=() ok=()
    need shadow || return
    site_val PASS_WARN_AGE 7; min=$REPLY
    if login_defs_get PASS_WARN_AGE && is_uint "$REPLY" && (( REPLY >= min )); then
        ok+=("/etc/login.defs: PASS_WARN_AGE $REPLY (expected $min or more)")
    else
        bad+=("/etc/login.defs: PASS_WARN_AGE ${REPLY:-not set}, expected $min or more")
    fi
    while IFS=: read -r name f3 f4 f5 f6 _; do
        if ! is_uint "$f6" || (( f6 < min )); then
            bad+=("user $name: PASS_WARN_AGE '${f6:-empty}' in /etc/shadow, expected $min or more")
        fi
    done < <(shadow_hash_rows)
    (( ${#bad[@]} )) || ok+=("every account with a password has a warning period of $min days or more")
    cap_lines 25 "${bad[@]}"
    if (( ${#bad[@]} )); then result "$id" FAIL "${CAPPED[@]}" "${ok[@]}"; else result "$id" PASS "${ok[@]}"; fi
}

# 5.4.1.4 Ensure strong password hashing algorithm is configured: ENCRYPT_METHOD SHA512 or YESCRYPT.
cus_5_4_1_4() {
    local id=$1 line
    line=$(grep -Pi -- '^\s*ENCRYPT_METHOD\s+\S+' "$R/etc/login.defs" 2>/dev/null | tail -n1)
    if [[ ${line^^} =~ ^[[:space:]]*ENCRYPT_METHOD[[:space:]]+(SHA512|YESCRYPT)([[:space:]]|$) ]]; then
        result "$id" PASS "/etc/login.defs: $line, expected SHA512 or YESCRYPT"
    else
        result "$id" FAIL "/etc/login.defs: ${line:-ENCRYPT_METHOD not set}, expected SHA512 or YESCRYPT"
    fi
}

# 5.4.1.5 Ensure inactive password lock is configured: INACTIVE 0..45 in the useradd
# defaults (what `useradd -D` prints) and in every account with a password hash.
cus_5_4_1_5() {
    local id=$1 max v name f3 f4 f5 f6 f7
    local -a bad=() ok=()
    need shadow || return
    site_val INACTIVE 45; max=$REPLY
    v=$(grep -Pio -- '^\s*INACTIVE\s*=\s*\K-?[0-9]+' "$R/etc/default/useradd" 2>/dev/null | tail -n1)
    if is_int "$v" && (( v >= 0 && v <= max )); then
        ok+=("/etc/default/useradd: INACTIVE=$v (expected 0 to $max)")
    else
        bad+=("/etc/default/useradd: INACTIVE=${v:-not set}, expected 0 to $max")
    fi
    while IFS=: read -r name f3 f4 f5 f6 f7; do
        if ! is_int "$f7" || (( f7 < 0 || f7 > max )); then
            bad+=("user $name: INACTIVE '${f7:-empty}' days in /etc/shadow, expected 0 to $max")
        fi
    done < <(shadow_hash_rows)
    (( ${#bad[@]} )) || ok+=("every account with a password locks after $max inactive days or fewer")
    cap_lines 25 "${bad[@]}"
    if (( ${#bad[@]} )); then result "$id" FAIL "${CAPPED[@]}" "${ok[@]}"; else result "$id" PASS "${ok[@]}"; fi
}

# 5.4.1.6 Ensure all users last password change date is in the past.
cus_5_4_1_6() {
    local id=$1 today name f3 f4
    local -a bad=()
    need shadow || return
    today=$((EPOCHSECONDS / 86400))
    while IFS=: read -r name f3 f4 _; do
        is_uint "$f3" || continue
        (( f3 > today )) && bad+=("user $name: last password change is day $f3 since 1970, which is in the future (today is day $today)")
    done < <(shadow_hash_rows)
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}"
    else
        result "$id" PASS "no account with a password has a last-change date in the future"
    fi
}

# ---- 5.4.2 root and system accounts -----------------------------------------
# 5.4.2.1 Ensure root is the only UID 0 account.
cus_5_4_2_1() {
    local id=$1 l name uid
    local -a hits=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name _ uid _ <<<"$l"
        [[ $uid == 0 ]] && hits+=("$name")
    done
    if [[ ${#hits[@]} -eq 1 && ${hits[0]} == root ]]; then
        result "$id" PASS "only root has UID 0"
    else
        result "$id" FAIL "accounts with UID 0: ${hits[*]:-none}, expected only root"
    fi
}

# 5.4.2.2 Ensure root is the only GID 0 account (sync, shutdown, halt, operator excluded).
cus_5_4_2_2() {
    local id=$1 l name gid
    local -a hits=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name _ _ gid _ <<<"$l"
        [[ $name =~ ^(sync|shutdown|halt|operator) ]] && continue
        [[ $gid == 0 ]] && hits+=("$name")
    done
    if [[ ${#hits[@]} -eq 1 && ${hits[0]} == root ]]; then
        result "$id" PASS "only root has primary GID 0"
    else
        result "$id" FAIL "accounts with primary GID 0: ${hits[*]:-none}, expected only root"
    fi
}

# 5.4.2.3 Ensure group root is the only GID 0 group.
cus_5_4_2_3() {
    local id=$1 l name gid
    local -a hits=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    for l in "${GROUP_L[@]}"; do
        IFS=: read -r name _ gid _ <<<"$l"
        [[ $gid == 0 ]] && hits+=("$name")
    done
    if [[ ${#hits[@]} -eq 1 && ${hits[0]} == root ]]; then
        result "$id" PASS "only group root has GID 0"
    else
        result "$id" FAIL "groups with GID 0: ${hits[*]:-none}, expected only root"
    fi
}

# 5.4.2.4 Ensure root account access is controlled: the root password is set (P) or
# the account is locked (L). passwd -S is not run; the status comes from /etc/shadow
# the same way passwd prints it (* or ! prefix = L, empty = NP).
shadow_status() { # shadow_status <password field> -> REPLY P|L|NP
    case $1 in
        '') REPLY=NP ;;
        '*'*|'!'*) REPLY=L ;;
        *) REPLY=P ;;
    esac
}
cus_5_4_2_4() {
    local id=$1 l name pw
    need shadow || return
    for l in "${SHADOW_L[@]}"; do
        IFS=: read -r name pw _ <<<"$l"
        if [[ $name == root ]]; then
            shadow_status "$pw"
            if [[ $REPLY == P || $REPLY == L ]]; then
                result "$id" PASS "root password status: $REPLY (P = password set, L = locked)"
            else
                result "$id" FAIL "root password status: NP (no password set), expected P or L"
            fi
            return
        fi
    done
    result "$id" FAIL "root has no entry in /etc/shadow"
}

# 5.4.2.5 Ensure root path integrity: root's PATH has no empty entry, trailing colon,
# '.', and every element is a root-owned directory with no group/other write.
cus_5_4_2_5() {
    local id=$1 rp el
    local -a bad=() ok=() elems
    _need_fact root_path || { result "$id" ERROR "root PATH unavailable: $NEED_ERR"; return; }
    rp=$(head -n1 "$FACT_FILE")
    [[ $rp == *::* ]] && bad+=("root's PATH contains an empty directory (::)")
    [[ $rp == *: ]] && bad+=("root's PATH contains a trailing colon")
    [[ ":$rp:" == *:.:* ]] && bad+=("root's PATH contains the current working directory (.)")
    IFS=':' read -ra elems <<<"$rp"
    for el in "${elems[@]}"; do
        [[ -z $el || $el == . ]] && continue
        if ! fstat "$el" || [[ $S_TYPE != d ]]; then
            bad+=("\"$el\" is not a directory")
            continue
        fi
        [[ $S_USER == root ]] || bad+=("directory $el is owned by $S_USER, expected root")
        if (( 8#$S_MODE & 8#0022 )); then
            bad+=("directory $el is mode $S_MODE4, expected 0755 or more restrictive")
        fi
    done
    (( ${#bad[@]} )) || ok+=("root PATH $rp: all elements are root-owned directories, mode 0755 or stricter")
    if (( ${#bad[@]} )); then result "$id" FAIL "${bad[@]}" "root PATH: $rp"; else result "$id" PASS "${ok[@]}"; fi
}

# 5.4.2.6 Ensure root user umask is configured: no umask less restrictive than 0027
# in /root/.profile and /root/.bashrc (the PDF's regular expression).
cus_5_4_2_6() {
    local id=$1 f hits
    local -a bad=() seen=()
    local rx='^\s*umask\s+((\d{1,2}(\d[^7]|[^2-7]\d)\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))'
    for f in /root/.profile /root/.bashrc; do
        [[ -r $R$f ]] || continue
        seen+=("$f")
        hits=$(grep -Pi -- "$rx" "$R$f")
        [[ -n $hits ]] && bad+=("$f: ${hits//$'\n'/ | }, less restrictive than umask 027")
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}"
    else
        result "$id" PASS "no umask less restrictive than 027 in ${seen[*]:-/root/.profile or /root/.bashrc (files do not exist)}"
    fi
}

# 5.4.2.7 Ensure system accounts do not have a valid login shell: accounts with
# UID below UID_MIN (or 65534), except root halt sync shutdown nfsnobody.
cus_5_4_2_7() {
    local id=$1 l name uid shell umin
    local -a bad=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    login_defs_get UID_MIN && umin=$REPLY || umin=1000
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name _ uid _ _ _ shell <<<"$l"
        [[ $name =~ ^(root|halt|sync|shutdown|nfsnobody)$ ]] && continue
        is_uint "$uid" || continue
        if (( uid < umin || uid == 65534 )) && [[ -n ${VALID_SHELL[$shell]+x} ]]; then
            bad+=("service account \"$name\" (UID $uid) has a valid shell: $shell")
        fi
    done
    cap_lines 25 "${bad[@]}"
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${CAPPED[@]}"
    else
        result "$id" PASS "no system account (UID below $umin) has a valid login shell"
    fi
}

# 5.4.2.8 Ensure accounts without a valid login shell are locked.
cus_5_4_2_8() {
    local id=$1 l name pw shell sh_of
    local -a bad=()
    local -A shell_of=()
    need shadow || return
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name _ _ _ _ _ shell <<<"$l"
        shell_of[$name]=$shell
    done
    for l in "${SHADOW_L[@]}"; do
        IFS=: read -r name pw _ <<<"$l"
        [[ $name == root ]] && continue
        [[ -n ${shell_of[$name]+x} ]] || continue
        [[ -n ${VALID_SHELL[${shell_of[$name]}]+x} ]] && continue
        shadow_status "$pw"
        [[ $REPLY == L ]] || bad+=("Account \"$name\" does not have a valid login shell (${shell_of[$name]:-none}) and is not locked")
    done
    cap_lines 25 "${bad[@]}"
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${CAPPED[@]}"
    else
        result "$id" PASS "every non-root account without a valid login shell is locked"
    fi
}

# ---- 5.4.3 shell environment ------------------------------------------------
# 5.4.3.2 Ensure default user shell timeout is configured.
# For every file that mentions TMOUT (/etc/*bashrc, /etc/profile, /etc/profile.d/*.sh):
# TMOUT=N with 0 < N <= 900, readonly and exported in the same file. The check
# passes when at least one file is complete and no file sets TMOUT incorrectly.
cus_5_4_3_2() {
    local id=$1 f max v ro ex good=0 vals
    local -a bad=() ok=() files=()
    site_val TMOUT_MAX 900; max=$REPLY
    shopt -s nullglob
    for f in "$R"/etc/*bashrc "$R/etc/profile" "$R"/etc/profile.d/*.sh; do
        [[ -f $f ]] && files+=("${f#"$R"}")
    done
    shopt -u nullglob
    for f in "${files[@]}"; do
        grep -Pqs -- '^([^#\n\r]+)?\bTMOUT\b' "$R$f" || continue
        vals=$(grep -Po -- '^([^#\n\r]+)?\bTMOUT=\K[0-9]+' "$R$f")
        ro=$(grep -P -- '^\s*(typeset\s-xr\sTMOUT=\d+|([^#\n\r]+)?\breadonly\s+TMOUT\b)' "$R$f")
        ex=$(grep -P -- '^\s*(typeset\s-xr\sTMOUT=\d+|([^#\n\r]+)?\bexport\b([^#\n\r]+\b)?TMOUT\b)' "$R$f")
        if [[ -z $vals ]]; then
            bad+=("$f: TMOUT is mentioned but not assigned a value in this file")
            continue
        fi
        local fileok=1
        for v in $vals; do
            if (( v > max || v <= 0 )); then
                bad+=("$f: TMOUT=$v, expected 1 to $max")
                fileok=0
            fi
        done
        [[ -n $ro ]] || { bad+=("$f: TMOUT is not marked readonly"); fileok=0; }
        [[ -n $ex ]] || { bad+=("$f: TMOUT is not exported"); fileok=0; }
        if (( fileok )); then ok+=("$f: TMOUT=${vals//$'\n'/,}, readonly and exported"); good=1; fi
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    elif (( good )); then
        result "$id" PASS "${ok[@]}"
    else
        result "$id" FAIL "TMOUT is not configured in ${files[*]:-/etc/profile, /etc/profile.d/*.sh or /etc/bashrc}, expected readonly exported TMOUT of at most $max seconds"
    fi
}

# 5.4.3.3 Ensure default user umask is configured: no umask less restrictive than 027
# in /etc/profile, /etc/profile.d/*.sh and /etc/bash.bashrc, and UMASK in login.defs.
# (The PDF names /etc/profile.d/ as a directory without -r; the files in it are checked.)
cus_5_4_3_3() {
    local id=$1 f hits
    local -a bad=() seen=()
    glob_files '/etc/profile' '/etc/profile.d/*.sh' '/etc/bash.bashrc'
    for f in "${GLOB[@]}"; do
        seen+=("$f")
        # \s++ is possessive: with plain \s+ the engine backtracks into the blanks and
        # reports a compliant "umask   027" (the PDF's regex has this flaw)
        hits=$(grep -Psi -- '^\s*umask\s++(?!0?[02367]7\b)' "$R$f")
        [[ -n $hits ]] && bad+=("$f: ${hits//$'\n'/ | }, expected 027 or more restrictive")
    done
    hits=$(grep -Psi -- '^\s*UMASK\s++(?!0?[02367]7\b)' "$R/etc/login.defs" 2>/dev/null)
    [[ -n $hits ]] && bad+=("/etc/login.defs: ${hits//$'\n'/ | }, expected 027 or more restrictive")
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}"
    else
        result "$id" PASS "no umask less restrictive than 027 in ${seen[*]} or /etc/login.defs"
    fi
}

man_ev_5_1_14() {
    if need_sshd; then
        local k=${SSHD[base:kexalgorithms]-}
        printf 'kexalgorithms: %s\n' "$k"
        [[ ,$k, == *,sntrup761x25519-sha512*,* || $k == *sntrup761x25519-sha512* ]] && printf 'sntrup761x25519-sha512 is offered\n' || printf 'sntrup761x25519-sha512 is NOT offered\n'
        [[ $k == *mlkem768x25519-sha256* ]] && printf 'mlkem768x25519-sha256 is offered\n' || printf 'mlkem768x25519-sha256 is NOT offered (required from OpenSSH 9.9)\n'
    fi
}

man_ev_5_3_3_2_3() {
    local f
    glob_files '/etc/security/pwquality.conf' '/etc/security/pwquality.conf.d/*.conf'
    for f in "${GLOB[@]}"; do
        grep -Psi -- '^\s*(minclass|[dulo]credit)\b' "$R$f" | sed "s|^|$f: |"
    done
    return 0
}
