#!/usr/bin/env bash
# lib/applicability.sh - derived flags and the applies_if evaluator.
#
# Flags are computed lazily on first use so that `--only 5.1.7` does not collect
# unrelated facts. A control whose condition is false is reported as N/A with the
# reason in the evidence.
# shellcheck disable=SC2034

declare -A FLAG=()
APPLIES_WHY=""

flag_get() { # flag_get NAME -> REPLY (empty + return 1 when it cannot be derived)
    local n=$1
    if [[ -z ${FLAG[$n]+x} ]]; then
        if ! declare -F "flag_$n" >/dev/null; then
            REPLY=""
            return 1
        fi
        "flag_$n" || { FLAG[$n]="?"; }
    fi
    REPLY=${FLAG[$n]}
    [[ $REPLY != "?" ]]
}

flag_TIME_DAEMON() {
    local v=${SITE[TIME_DAEMON]:-auto} out=""
    if [[ $v != auto ]]; then
        FLAG[TIME_DAEMON]=$v
        return 0
    fi
    need_units || return 1
    if unit_is_enabled chrony.service || unit_is_active chrony.service; then out=chrony; fi
    if unit_is_enabled systemd-timesyncd.service || unit_is_active systemd-timesyncd.service; then
        out=${out:+$out+}timesyncd
    fi
    FLAG[TIME_DAEMON]=${out:-none}
}

flag_LOGGER() {
    local v=${SITE[LOGGER]:-auto}
    if [[ $v != auto ]]; then
        FLAG[LOGGER]=$v
        return 0
    fi
    need_dpkg && need_units || return 1
    if pkg_installed rsyslog && unit_is_active rsyslog.service; then
        FLAG[LOGGER]=rsyslog
    else
        FLAG[LOGGER]=journald
    fi
}

flag_HAS_GDM() { need_dpkg || return 1; pkg_installed gdm3 && FLAG[HAS_GDM]=1 || FLAG[HAS_GDM]=0; }
flag_HAS_CRON() { need_dpkg || return 1; pkg_installed cron && FLAG[HAS_CRON]=1 || FLAG[HAS_CRON]=0; }
flag_HAS_AT() { need_dpkg || return 1; pkg_installed at && FLAG[HAS_AT]=1 || FLAG[HAS_AT]=0; }
flag_HAS_COREDUMP() {
    need_dpkg || return 1
    pkg_installed systemd-coredump && FLAG[HAS_COREDUMP]=1 || FLAG[HAS_COREDUMP]=0
}
flag_HAS_MTA() {
    need_dpkg || return 1
    local p
    FLAG[HAS_MTA]=0
    for p in postfix exim4 exim4-daemon-light exim4-daemon-heavy sendmail; do
        pkg_installed "$p" && FLAG[HAS_MTA]=1
    done
    return 0
}

# IPv6 per 3.1.1: not enabled when /sys/module/ipv6/parameters/disable is not 0,
# or when both disable_ipv6 sysctls are 1.
flag_IPV6_ENABLED() {
    local en=1
    if ! grep -Pqs '^\s*0\b' -- "$R/sys/module/ipv6/parameters/disable"; then en=0; fi
    if need_sysctl; then
        if [[ ${SYSCTL_RUN[net.ipv6.conf.all.disable_ipv6]-} == 1 && ${SYSCTL_RUN[net.ipv6.conf.default.disable_ipv6]-} == 1 ]]; then
            en=0
        fi
    fi
    FLAG[IPV6_ENABLED]=$en
}

# applies <applies_if>: comma separated AND of NAME=value | NAME~value (contains)
# | NAME!=value. Returns 0 when the control applies. Sets APPLIES_WHY on false.
applies() {
    local cond=$1 c n op v
    local -a conds
    APPLIES_WHY=""
    [[ -z $cond || $cond == "-" ]] && return 0
    IFS=',' read -ra conds <<<"$cond"
    for c in "${conds[@]}"; do
        if [[ $c =~ ^([A-Z0-9_]+)(!=|=|~)(.*)$ ]]; then
            n=${BASH_REMATCH[1]} op=${BASH_REMATCH[2]} v=${BASH_REMATCH[3]}
        else
            APPLIES_WHY="invalid applies_if condition '$c'"
            return 2
        fi
        if ! flag_get "$n"; then
            APPLIES_WHY="cannot derive applicability flag $n"
            return 2
        fi
        case $op in
            =) [[ $REPLY == "$v" ]] || { APPLIES_WHY="condition $c is false ($n=$REPLY)"; return 1; } ;;
            '!=') [[ $REPLY != "$v" ]] || { APPLIES_WHY="condition $c is false ($n=$REPLY)"; return 1; } ;;
            '~') [[ $REPLY == *"$v"* ]] || { APPLIES_WHY="condition $c is false ($n=$REPLY)"; return 1; } ;;
        esac
    done
    return 0
}
