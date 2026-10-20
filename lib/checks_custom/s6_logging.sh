#!/usr/bin/env bash
# lib/checks_custom/s6_logging.sh - custom checks, benchmark section 6.
# shellcheck disable=SC2034,SC2154

# rsyslog_files: RSYS = /etc/rsyslog.conf plus /etc/rsyslog.d/*.conf that exist
rsyslog_files() {
    RSYS=()
    local f
    [[ -r $R/etc/rsyslog.conf ]] && RSYS+=("/etc/rsyslog.conf")
    shopt -s nullglob
    local -a d
    mapfile -t d < <(printf '%s\n' "$R"/etc/rsyslog.d/*.conf | LC_ALL=C sort)
    shopt -u nullglob
    for f in "${d[@]}"; do [[ -n $f ]] && RSYS+=("${f#"$R"}"); done
}

# 6.1.2.3 Ensure rsyslog log file creation mode is configured: a $FileCreateMode of
# 0640 or more restrictive; without the directive the default 0644 applies.
cus_6_1_2_3() {
    local id=$1 f line val ex
    local -a bad=() ok=()
    rsyslog_files
    for f in "${RSYS[@]}"; do
        while IFS= read -r line; do
            val=$(grep -Po -- '\$FileCreateMode\s+\K0[0-7]{3}' <<<"$line")
            if oct_excess "$val" 640; then
                ok+=("$f: \$FileCreateMode $val")
            else
                bad+=("$f: \$FileCreateMode $val grants $OCT_EX beyond 0640")
            fi
        done < <(grep -Psi -- '^\s*\$FileCreateMode\s+0[0-7]{3}\b' "$R$f")
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    elif (( ${#ok[@]} == 0 )); then
        result "$id" FAIL "no \$FileCreateMode directive in /etc/rsyslog.conf or /etc/rsyslog.d/*.conf; the default 0644 applies, expected 0640 or more restrictive"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# 6.1.2.6 Ensure rsyslog is not configured to receive logs from a remote client:
# no imtcp / imudp module or input in advanced or legacy format.
cus_6_1_2_6() {
    local id=$1 f rx
    local -a bad=() rxs=(
        '^\s*module\(load="?imtcp"?\)' '^\s*input\(type="?imtcp"?\b'
        '^\s*module\(load="?imudp"?\)' '^\s*input\(type="?imudp"?\b'
        '^\s*\$ModLoad\s+imtcp\b' '^\s*\$InputTCPServerRun\b'
        '^\s*\$ModLoad\s+imudp\b' '^\s*\$UDPServerRun\b')
    rsyslog_files
    for f in "${RSYS[@]}"; do
        for rx in "${rxs[@]}"; do
            while IFS= read -r line; do
                bad+=("$f: $line")
            done < <(grep -Psi -- "$rx" "$R$f")
        done
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "rsyslog is set up to receive remote logs:" "${bad[@]}"
    else
        result "$id" PASS "no imtcp/imudp module or input (advanced or legacy format) in ${RSYS[*]:-the rsyslog configuration}"
    fi
}

# 6.1.3.1 Ensure access to all logfiles has been configured.
# Port of the PDF script (tools/reference/cis_6.1.3.1_audit.sh): the fact logfiles
# lists the files the PDF's find reports; the per-file mask and the allowed
# owner/group depend on the file name. Owner/group alternatives are matched in full.
cus_6_1_3_1() {
    local id=$1 mode user group path base mask auser agroup sh maxo
    local -a bad=() sub
    local -A shell_of=()
    _need_fact logfiles || { result "$id" ERROR "log file list unavailable: $NEED_ERR"; return; }
    acct_load || { result "$id" ERROR "cannot read /etc/passwd: $NEED_ERR"; return; }
    local l
    for l in "${PASSWD_L[@]}"; do
        IFS=: read -r u _ _ _ _ _ sh <<<"$l"
        shell_of[$u]=$sh
    done
    local -A etc_shell=()
    if [[ -r $R/etc/shells ]]; then
        while IFS= read -r l; do [[ $l == /* ]] && etc_shell[$l]=1; done <"$R/etc/shells"
    fi
    while IFS=$'\t' read -r mode user group path; do
        [[ -n $path ]] || continue
        base=${path##*/}
        if [[ ${path%/*} =~ /apt[[:space:]]*$ ]]; then
            mask=0133 auser="root" agroup="root|adm"
        else
            case $base in
                lastlog|lastlog.*|wtmp|wtmp.*|wtmp-*|btmp|btmp.*|btmp-*|README)
                    mask=0113 auser="root" agroup="root|utmp" ;;
                cloud-init.log*|localmessages*|waagent.log*)
                    mask=0133 auser="root|syslog" agroup="root|adm" ;;
                secure|secure.*|secure-*|auth.log|syslog|messages)
                    mask=0137 auser="root|syslog" agroup="root|adm" ;;
                SSSD|sssd)
                    mask=0117 auser="root|SSSD" agroup="root|SSSD" ;;
                gdm|gdm3)
                    mask=0117 auser="root" agroup="root|gdm|gdm3" ;;
                *.journal|*.journal~)
                    mask=0137 auser="root" agroup="root|systemd-journal" ;;
                *)
                    mask=0137 auser="root|syslog" agroup="root|adm"
                    sh=${shell_of[$user]-}
                    # files of service accounts (no valid login shell) may belong to that account
                    if [[ $user == root ]] || [[ -n ${shell_of[$user]+x} && -z ${etc_shell[$sh]+x} ]]; then
                        list_has "$auser" "$user" || auser="root|syslog|$user"
                        list_has "$agroup" "$group" || agroup="root|adm|$group"
                    fi ;;
            esac
        fi
        sub=()
        printf -v maxo '%o' $((0777 & ~8#$mask))
        if ! oct_excess "$mode" "$maxo"; then
            mode4 "$mode"
            printf -v maxo '%04o' $((0777 & ~8#$mask))
            sub+=("mode $M4 should be $maxo or more restrictive")
        fi
        list_has "$auser" "$user" || sub+=("owned by $user, should be ${auser//|/ or }")
        list_has "$agroup" "$group" || sub+=("group owned by $group, should be ${agroup//|/ or }")
        (( ${#sub[@]} )) && bad+=("$path: $(IFS=';'; echo "${sub[*]}")")
    done <"$FACT_FILE"
    cap_lines 30 "${bad[@]}"
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${CAPPED[@]}"
    else
        result "$id" PASS "all files in /var/log have appropriate permissions and ownership"
    fi
}

# 6.3.2 Ensure filesystem integrity is regularly checked: dailyaidecheck.timer enabled
# and active, dailyaidecheck.service static or enabled.
cus_6_3_2() {
    local id=$1 ts ss
    local -a bad=() ok=()
    need units || return
    ts=${UNIT_FILE_STATE[dailyaidecheck.timer]-not found}
    ss=${UNIT_FILE_STATE[dailyaidecheck.service]-not found}
    [[ $ts == enabled ]] && ok+=("dailyaidecheck.timer is enabled") || bad+=("dailyaidecheck.timer: $ts, expected enabled")
    [[ $ss == static || $ss == enabled ]] && ok+=("dailyaidecheck.service is $ss") || bad+=("dailyaidecheck.service: $ss, expected static or enabled")
    if unit_is_active dailyaidecheck.timer; then ok+=("dailyaidecheck.timer is active"); else bad+=("dailyaidecheck.timer is not active"); fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

man_ev_6_1_1_1_4() {
    local f
    for f in /etc/tmpfiles.d/systemd.conf /usr/lib/tmpfiles.d/systemd.conf; do
        [[ -r $R$f ]] || continue
        local type path perm rest
        while read -r type path perm rest; do
            [[ $type == f && $perm =~ ^0?[0-7]{3,4}$ ]] || continue
            fexists "$path" || continue
            (( 8#$S_MODE & 8#0137 )) && printf '%s: mode %s grants more than 0640 (defined in %s)\n' "$path" "$S_MODE4" "$f"
        done <"$R$f"
    done
    return 0
}

man_ev_6_1_1_1_5() {
    local f
    glob_files '/etc/systemd/journald.conf' '/etc/systemd/journald.conf.d/*.conf'
    for f in "${GLOB[@]}"; do
        grep -Psi -- '\b(SystemMaxUse|SystemKeepFree|RuntimeMaxUse|RuntimeKeepFree|MaxFileSec)=' "$R$f" | sed "s|^|$f: |"
    done
    return 0
}

man_ev_6_1_2_4() {
    rsyslog_files
    printf 'rsyslog configuration files: %s\n' "${RSYS[*]:-none}"
}

man_ev_6_1_2_5() {
    local f hits
    rsyslog_files
    for f in "${RSYS[@]}"; do
        hits=$(grep -Psi -- '^\s*\*\.\*\s+@{1,2}\S+' "$R$f"; grep -Psi -- 'target="?[^#"[:space:]]+' "$R$f" | head -n 3)
        [[ -n $hits ]] && printf '%s: %s\n' "$f" "${hits//$'\n'/ | }"
    done
    return 0
}

man_ev_6_1_2_7() {
    printf 'logrotate configuration: %s\n' "$( [[ -r $R/etc/logrotate.conf ]] && echo /etc/logrotate.conf present || echo missing)"
}
