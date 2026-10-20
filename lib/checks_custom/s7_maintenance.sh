#!/usr/bin/env bash
# lib/checks_custom/s7_maintenance.sh - custom checks, benchmark section 7.
# shellcheck disable=SC2034,SC2154

# 7.1.11 Ensure world writable files and directories are secured.
# Port of tools/reference/cis_7.1.11_audit.sh: the fact fs_world holds world-writable
# files (f) and world-writable directories without the sticky bit (d), found with
# -xdev on local mounts only (run/tmp/var/tmp and network or pseudo filesystems skipped).
cus_7_1_11() {
    local id=$1 kind path
    local -a files=() dirs=()
    _need_fact fs_world || { result "$id" ERROR "filesystem walk failed or timed out: $NEED_ERR (raise --timeout)"; return; }
    while IFS=$'\t' read -r kind path; do
        case $kind in f) files+=("$path") ;; d) dirs+=("$path") ;; esac
    done <"$FACT_FILE"
    local -a ev=()
    if (( ${#files[@]} )); then
        cap_lines 20 "${files[@]}"
        ev+=("${#files[@]} world writable files, expected none:" "${CAPPED[@]}")
    fi
    if (( ${#dirs[@]} )); then
        cap_lines 20 "${dirs[@]}"
        ev+=("${#dirs[@]} world writable directories without the sticky bit, expected none:" "${CAPPED[@]}")
    fi
    if (( ${#ev[@]} )); then
        result "$id" FAIL "${ev[@]}"
    else
        result "$id" PASS "no world writable files and no world writable directories without the sticky bit on local filesystems"
    fi
}

# 7.1.12 Ensure no files or directories without an owner and a group exist.
cus_7_1_12() {
    local id=$1 kind path
    local -a nu=() ng=() ev=()
    _need_fact fs_nouser || { result "$id" ERROR "filesystem walk failed or timed out: $NEED_ERR (raise --timeout)"; return; }
    while IFS=$'\t' read -r kind path; do
        case $kind in u) nu+=("$path") ;; g) ng+=("$path") ;; esac
    done <"$FACT_FILE"
    if (( ${#nu[@]} )); then cap_lines 20 "${nu[@]}"; ev+=("${#nu[@]} files or directories without an owner, expected none:" "${CAPPED[@]}"); fi
    if (( ${#ng[@]} )); then cap_lines 20 "${ng[@]}"; ev+=("${#ng[@]} files or directories without a group, expected none:" "${CAPPED[@]}"); fi
    if (( ${#ev[@]} )); then
        result "$id" FAIL "${ev[@]}"
    else
        result "$id" PASS "no files or directories without an owner or a group exist on local filesystems"
    fi
}

man_ev_7_1_13() {
    local kind path ns=0 ng=0 shown=0 approved=""
    if ! _need_fact fs_suid; then
        printf 'SUID/SGID list unavailable: %s\n' "$NEED_ERR"
        return
    fi
    [[ -n ${SITE[APPROVED_SUID_FILE]-} && -r $R${SITE[APPROVED_SUID_FILE]} ]] && approved=$R${SITE[APPROVED_SUID_FILE]}
    while IFS=$'\t' read -r kind path; do
        [[ $kind == suid ]] && ns=$((ns + 1))
        [[ $kind == sgid ]] && ng=$((ng + 1))
        if [[ -n $approved ]] && grep -qxF -- "$path" "$approved"; then continue; fi
        if (( shown < 40 )); then
            printf '%s: %s\n' "$kind" "$path"
            shown=$((shown + 1))
        fi
    done <"$FACT_FILE"
    printf '%d SUID and %d SGID files found%s\n' "$ns" "$ng" "${approved:+ (files in APPROVED_SUID_FILE are not listed above)}"
}

# ---- 7.2 local user and group settings --------------------------------------
# 7.2.1 Ensure accounts in /etc/passwd use shadowed passwords.
cus_7_2_1() {
    local id=$1 l name pw
    local -a bad=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name pw _ <<<"$l"
        [[ $pw != x ]] && bad+=("User \"$name\" is not set to shadowed passwords (password field is '${pw:-empty}')")
    done
    if (( ${#bad[@]} )); then result "$id" FAIL "${bad[@]}"; else result "$id" PASS "all accounts in /etc/passwd use 'x' (shadowed passwords)"; fi
}

# 7.2.2 Ensure /etc/shadow password fields are not empty.
cus_7_2_2() {
    local id=$1 l name pw
    local -a bad=()
    need shadow || return
    for l in "${SHADOW_L[@]}"; do
        IFS=: read -r name pw _ <<<"$l"
        [[ -z $pw ]] && bad+=("$name does not have a password")
    done
    if (( ${#bad[@]} )); then result "$id" FAIL "${bad[@]}"; else result "$id" PASS "no account has an empty password field in /etc/shadow"; fi
}

# 7.2.3 Ensure all groups in /etc/passwd exist in /etc/group.
cus_7_2_3() {
    local id=$1 l name gid
    local -a bad=()
    local -A gids=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    for l in "${GROUP_L[@]}"; do
        IFS=: read -r _ _ gid _ <<<"$l"
        gids[$gid]=1
    done
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name _ _ gid _ <<<"$l"
        [[ -n ${gids[$gid]+x} ]] || bad+=("User \"$name\" has GID \"$gid\" which does not exist in /etc/group")
    done
    if (( ${#bad[@]} )); then result "$id" FAIL "${bad[@]}"; else result "$id" PASS "every primary GID in /etc/passwd exists in /etc/group"; fi
}

# 7.2.4 Ensure shadow group is empty: no members and no user with it as primary group.
cus_7_2_4() {
    local id=$1 l name gid members sgid=""
    local -a bad=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    for l in "${GROUP_L[@]}"; do
        IFS=: read -r name _ gid members <<<"$l"
        if [[ $name == shadow ]]; then
            sgid=$gid
            [[ -n $members ]] && bad+=("group shadow has members: $members")
        fi
    done
    if [[ -n $sgid ]]; then
        for l in "${PASSWD_L[@]}"; do
            IFS=: read -r name _ _ gid _ <<<"$l"
            [[ $gid == "$sgid" ]] && bad+=("user \"$name\" has the shadow group as primary group")
        done
    fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}"
    elif [[ -z $sgid ]]; then
        result "$id" PASS "there is no shadow group"
    else
        result "$id" PASS "group shadow (GID $sgid) has no members and is no user's primary group"
    fi
}

# dup_check <file-lines-array-name> <field> <label> ... prints duplicates
dup_report() { # dup_report <"u"|"g"> <field index (1 name, 3 id)> <label>
    local -n src=$1
    local field=$2 label=$3 l key name
    local -A count=() names=()
    DUPS=()
    for l in "${src[@]}"; do
        IFS=: read -ra fld <<<"$l"
        key=${fld[$((field - 1))]}
        name=${fld[0]}
        count[$key]=$(( ${count[$key]:-0} + 1 ))
        names[$key]+="$name "
    done
    for key in "${!count[@]}"; do
        (( count[$key] > 1 )) && DUPS+=("Duplicate $label: \"$key\" ${field/3/Names}: \"${names[$key]% }\"")
    done
    return 0
}

# 7.2.5 Ensure no duplicate UIDs exist.
cus_7_2_5() {
    need acct || { result "$1" ERROR "cannot read account files: $NEED_ERR"; return; }
    dup_report PASSWD_L 3 UID
    if (( ${#DUPS[@]} )); then result "$1" FAIL "${DUPS[@]}"; else result "$1" PASS "no UID is used by more than one account"; fi
}
# 7.2.6 Ensure no duplicate GIDs exist.
cus_7_2_6() {
    need acct || { result "$1" ERROR "cannot read account files: $NEED_ERR"; return; }
    dup_report GROUP_L 3 GID
    if (( ${#DUPS[@]} )); then result "$1" FAIL "${DUPS[@]}"; else result "$1" PASS "no GID is used by more than one group"; fi
}
# 7.2.7 Ensure no duplicate user names exist.
cus_7_2_7() {
    need acct || { result "$1" ERROR "cannot read account files: $NEED_ERR"; return; }
    dup_report PASSWD_L 1 "user name"
    if (( ${#DUPS[@]} )); then result "$1" FAIL "${DUPS[@]}"; else result "$1" PASS "no user name appears more than once in /etc/passwd"; fi
}
# 7.2.8 Ensure no duplicate group names exist.
cus_7_2_8() {
    need acct || { result "$1" ERROR "cannot read account files: $NEED_ERR"; return; }
    dup_report GROUP_L 1 "group name"
    if (( ${#DUPS[@]} )); then result "$1" FAIL "${DUPS[@]}"; else result "$1" PASS "no group name appears more than once in /etc/group"; fi
}

# 7.2.9 Ensure local interactive user home directories are configured: the directory
# exists, is owned by the user and is mode 0750 or more restrictive.
cus_7_2_9() {
    local id=$1 l name home shell n=0
    local -a bad=()
    need acct || { result "$id" ERROR "cannot read account files: $NEED_ERR"; return; }
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name _ _ _ _ home shell <<<"$l"
        [[ -n ${VALID_SHELL[$shell]+x} ]] || continue
        n=$((n + 1))
        if ! fstat "$home" || [[ $S_TYPE != d ]]; then
            bad+=("User \"$name\" home directory \"$home\" doesn't exist")
            continue
        fi
        [[ $S_USER == "$name" ]] || bad+=("User \"$name\" home \"$home\" is owned by \"$S_USER\"")
        (( 8#$S_MODE & 8#0027 )) && bad+=("User \"$name\" home \"$home\" is mode $S_MODE4, should be 0750 or more restrictive")
    done
    cap_lines 30 "${bad[@]}"
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${CAPPED[@]}"
    else
        result "$id" PASS "$n interactive users: all home directories exist, are owned by the user and are mode 0750 or stricter"
    fi
}

# primary_group_of <user> -> REPLY
primary_group_of() {
    local l name gid g gname ggid
    REPLY=""
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r name _ _ gid _ <<<"$l"
        if [[ $name == "$1" ]]; then
            for g in "${GROUP_L[@]}"; do
                IFS=: read -r gname _ ggid _ <<<"$g"
                [[ $ggid == "$gid" ]] && { REPLY=$gname; return 0; }
            done
        fi
    done
    return 1
}

REMOTE_FS="nfs nfs4 cifs smbfs smb3 fuse.sshfs afs ncpfs glusterfs ceph"

# home_dot_scan <f|d> -> HD_BAD, HD_WARN, HD_SKIP, HD_USERS
# Reads the home_dots fact: "home user path fstype" lines, then "kind user mode owner group path".
home_dot_scan() {
    local want=$1 kind user a b c d mask max pg t
    HD_BAD=() HD_WARN=() HD_SKIP=() HD_USERS=0
    _need_fact home_dots || return 1
    acct_load || return 1
    # first pass: "home <user> <path> <fstype>" lines; homes on remote filesystems are skipped
    local -A remote=()
    while IFS=$'\t' read -r kind user a b; do
        [[ $kind == home ]] || continue
        HD_USERS=$((HD_USERS + 1))
        for t in $REMOTE_FS; do
            if [[ $b == "$t" ]]; then
                remote[$user]=1
                HD_SKIP+=("User \"$user\" home \"$a\" skipped (remote/network filesystem: $b)")
            fi
        done
    done <"$FACT_FILE"
    local name base
    while IFS=$'\t' read -r kind user a b c d; do
        [[ $kind == "$want" ]] || continue
        [[ -n ${remote[$user]+x} ]] && continue
        # a = mode, b = owner, c = group, d = path
        base=${d##*/}
        if [[ $want == f ]]; then
            case $base in
                .forward|.rhosts) HD_BAD+=("User \"$user\": file \"$d\" exists"); continue ;;
                .netrc|.bash_history) mask=0177 ;;
                *) mask=0133 ;;
            esac
        else
            case $base in .ssh) mask=0077 ;; *) mask=0027 ;; esac
        fi
        primary_group_of "$user" && pg=$REPLY || pg=""
        local -a sub=()
        max=$(printf '%04o' $((0777 & ~8#$mask)))
        if (( 8#$a & 8#$mask )); then mode4 "$a"; sub+=("is mode $M4 and should be mode $max or more restrictive"); fi
        [[ $b == "$user" ]] || sub+=("owned by \"$b\" and should be owned by \"$user\"")
        [[ -z $pg || $c == "$pg" ]] || sub+=("group owned by \"$c\" and should be group owned by \"$pg\"")
        if (( ${#sub[@]} )); then
            HD_BAD+=("User \"$user\": \"$d\" $(IFS=';'; echo "${sub[*]}")")
        elif [[ $base == .netrc ]]; then
            HD_WARN+=("User \"$user\": file \"$d\" exists (mode and owner are fine; confirm it follows site policy)")
        fi
    done <"$FACT_FILE"
    return 0
}

# 7.2.10 Ensure local interactive user dot files access is configured: no .forward,
# .rhosts; .netrc and .bash_history 0600 or stricter; other dot files 0644 or stricter;
# owned by the user and group-owned by the user's primary group.
cus_7_2_10() {
    local id=$1
    if ! home_dot_scan f; then
        result "$id" ERROR "home directory scan unavailable: ${NEED_ERR:-fact home_dots missing}"
        return
    fi
    cap_lines 30 "${HD_BAD[@]}"
    if (( ${#HD_BAD[@]} )); then
        result "$id" FAIL "${CAPPED[@]}" "${HD_WARN[@]}" "${HD_SKIP[@]}"
    else
        result "$id" PASS "dot files of $HD_USERS local interactive users are configured correctly" "${HD_WARN[@]}" "${HD_SKIP[@]}"
    fi
}

# 7.2.11 Ensure local interactive user dot directories access is configured:
# dot directories 0750 or stricter, .ssh 0700 or stricter, owned by the user and
# group-owned by the user's primary group.
cus_7_2_11() {
    local id=$1
    if ! home_dot_scan d; then
        result "$id" ERROR "home directory scan unavailable: ${NEED_ERR:-fact home_dots missing}"
        return
    fi
    cap_lines 30 "${HD_BAD[@]}"
    if (( ${#HD_BAD[@]} )); then
        result "$id" FAIL "${CAPPED[@]}" "${HD_SKIP[@]}"
    else
        result "$id" PASS "dot directories of $HD_USERS local interactive users are configured correctly" "${HD_SKIP[@]}"
    fi
}
