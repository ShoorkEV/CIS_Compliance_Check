#!/usr/bin/env bash
# lib/checks_custom/s2_services.sh - custom checks, benchmark section 2.
# shellcheck disable=SC2034,SC2154

# mta_loopback_only <setting text>: every address token must be a loopback address.
mta_loopback_only() {
    local t v=${1#*=} 
    v=${v//[<;,]/ }
    [[ -n ${v//[[:space:]]/} ]] || return 0
    for t in $v; do
        t=${t#[}; t=${t%]}
        case ${t,,} in
            loopback-only|localhost|127.*|::1) ;;
            *) return 1 ;;
        esac
    done
    return 0
}

# 2.1.22 Ensure mail transfer agents are configured for local-only mode.
# Ports 25, 465 and 587 must not listen on a non-loopback address, and the MTA's own
# interface setting must not bind all interfaces. Deviation from the PDF script: its
# regex accepts 0.0.0.0 and rejects 127.0.0.1; this port accepts loopback values only.
cus_2_1_22() {
    local id=$1 port line local_addr cfg
    local -a f
    local -a bad=() ok=()
    need ss || return
    for port in 25 465 587; do
        local nonloop=0 any=0
        while IFS= read -r line; do
            # Netid State Recv-Q Send-Q Local:Port Peer:Port Process
            read -ra f <<<"$line"
            local_addr=${f[4]-}
            [[ $local_addr == *:"$port" ]] || continue
            any=1
            case ${local_addr%:*} in
                127.0.0.1|'[::1]'|::1) ;;
                *) nonloop=1; bad+=("port $port listens on $local_addr (non-loopback)") ;;
            esac
        done <"$FACT_FILE"
        (( any && ! nonloop )) && ok+=("port $port listens on loopback only")
        (( any )) || ok+=("nothing listens on port $port")
    done
    if fact mta_cfg && [[ -s $FACT_FILE ]]; then
        cfg=$(head -n1 "$FACT_FILE")
        if mta_loopback_only "${cfg#*: }"; then
            ok+=("MTA interface setting is loopback only: $cfg")
        else
            bad+=("MTA is bound to a non-loopback interface setting: $cfg")
        fi
    else
        ok+=("no MTA configuration found (MTA not detected or not in use)")
    fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

man_ev_2_1_23() {
    if need_ss; then
        printf 'listening sockets (ss -plntu): %s\n' "$(wc -l <"$FACT_FILE" | tr -d ' ')"
        local line
        local -a f
        while IFS= read -r line; do
            read -ra f <<<"$line"
            printf '%s %s %s\n' "${f[0]-}" "${f[4]-}" "${f[*]:6}"
        done <"$FACT_FILE"
        if [[ -n ${SITE[APPROVED_LISTENERS]-} ]]; then
            local e proto port found
            local -a ents
            IFS=',' read -ra ents <<<"${SITE[APPROVED_LISTENERS]}"
            while IFS= read -r line; do
                read -ra f <<<"$line"
                proto=${f[0]-} port=${f[4]##*:}
                found=0
                for e in "${ents[@]}"; do [[ $e == "$proto:$port" ]] && found=1; done
                (( found )) || printf 'NOT in APPROVED_LISTENERS: %s %s\n' "$proto" "${f[4]-}"
            done <"$FACT_FILE"
        else
            printf 'APPROVED_LISTENERS is not set in site.conf; compare the list with site policy by hand\n'
        fi
    else
        printf 'ss output unavailable\n'
    fi
}

# 2.3.1.1 Ensure a single time synchronization daemon is in use.
# "In use" means enabled or active, as in the PDF script. Exactly one of
# systemd-timesyncd.service and chrony.service must be in use.
cus_2_3_1_1() {
    local id=$1 d u s
    local -a use=() info=()
    need units || return
    for u in systemd-timesyncd.service chrony.service; do
        unit_describe "$u"
        if unit_is_enabled "$u" || unit_is_active "$u"; then
            use+=("$u")
            info+=("$u is in use ($REPLY enabled-state/active-state)")
        else
            info+=("$u is not enabled and not active ($REPLY)")
        fi
    done
    case ${#use[@]} in
        1) result "$id" PASS "only one time sync daemon is in use: ${use[0]}" "${info[@]}" ;;
        0) result "$id" FAIL "no time sync daemon is in use, expected exactly one of chrony or systemd-timesyncd" "${info[@]}" ;;
        *) result "$id" FAIL "more than one time sync daemon is in use, expected exactly one" "${info[@]}" ;;
    esac
}

# 2.3.3.1 Ensure chrony is configured: a server or pool line must exist in
# /etc/chrony/chrony.conf or in files below its confdir/sourcedir directories.
cus_2_3_3_1() {
    local id=$1 conf=/etc/chrony/chrony.conf f d line path
    local -a files=("$conf") hits=() dirs=()
    if [[ ! -r $R$conf ]]; then
        result "$id" FAIL "$conf does not exist or is not readable"
        return
    fi
    while read -r _ path; do
        [[ -n $path ]] && dirs+=("$path")
    done < <(grep -Pi -- '^\s*(confdir|sourcedir)\s+\S+' "$R$conf" | awk '{print $1, $2}')
    shopt -s nullglob
    for d in "${dirs[@]}"; do
        if [[ -d $R$d ]]; then
            for f in "$R$d"/*; do [[ -f $f ]] && files+=("${f#"$R"}"); done
        else
            for f in $R$d; do [[ -f $f ]] && files+=("${f#"$R"}"); done
        fi
    done
    shopt -u nullglob
    for f in "${files[@]}"; do
        while IFS= read -r line; do
            hits+=("$f: $line")
        done < <(grep -Pi -- '^\s*(server|pool)(\s+|\s*:\s*).+\b' "$R$f" 2>/dev/null)
    done
    if (( ${#hits[@]} )); then
        result "$id" PASS "time source configured:" "${hits[@]}" "verify the servers against site policy"
    else
        result "$id" FAIL "no 'server' or 'pool' line in ${files[*]}, expected an authorized time server"
    fi
}

# 2.3.3.2 Ensure chrony is running as user _chrony: no chronyd process may run as another user.
cus_2_3_3_2() {
    local id=$1 user args cmd
    local -a bad=() seen=()
    _need_fact ps_chronyd || { result "$id" ERROR "process list unavailable: $NEED_ERR"; return; }
    while read -r user args; do
        cmd=${args%% *}
        [[ ${cmd##*/} == chronyd ]] || continue
        if [[ $user == _chrony ]]; then
            seen+=("chronyd runs as $user")
        else
            bad+=("chronyd process runs as $user, expected _chrony: $args")
        fi
    done <"$FACT_FILE"
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${seen[@]}"
    elif (( ${#seen[@]} )); then
        result "$id" PASS "${seen[@]}"
    else
        result "$id" PASS "no chronyd process is running, so none runs as another user"
    fi
}

# 2.4.1.9 Ensure access to crontab is configured (cron.allow must exist, cron.deny
# need not; both 0640 or stricter, root:root or root:crontab).
cus_2_4_1_9() {
    local id=$1
    local -a bad=() ok=() PERM_OK=() PERM_BAD=()
    if ! perm_eval /etc/cron.allow 640 root "root|crontab"; then
        bad+=("/etc/cron.allow does not exist, expected it with mode 0640 or stricter, root:root or root:crontab")
    fi
    bad+=("${PERM_BAD[@]}")
    ok+=("${PERM_OK[@]}")
    PERM_OK=() PERM_BAD=()
    if perm_eval /etc/cron.deny 640 root "root|crontab"; then
        bad+=("${PERM_BAD[@]}")
        ok+=("${PERM_OK[@]}")
    else
        ok+=("/etc/cron.deny does not exist")
    fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# 2.4.2.1 Ensure access to at is configured (at.allow must exist, at.deny need not;
# both 0640 or stricter, root:daemon or root:root).
cus_2_4_2_1() {
    local id=$1
    local -a bad=() ok=() PERM_OK=() PERM_BAD=()
    if ! perm_eval /etc/at.allow 640 root "daemon|root"; then
        bad+=("/etc/at.allow does not exist, expected it with mode 0640 or stricter, root:daemon or root:root")
    fi
    bad+=("${PERM_BAD[@]}")
    ok+=("${PERM_OK[@]}")
    PERM_OK=() PERM_BAD=()
    if perm_eval /etc/at.deny 640 root "daemon|root"; then
        bad+=("${PERM_BAD[@]}")
        ok+=("${PERM_OK[@]}")
    else
        ok+=("/etc/at.deny does not exist")
    fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}
