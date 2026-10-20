#!/usr/bin/env bash
# lib/checks_custom/s3_network.sh - custom checks, benchmark section 3.
# shellcheck disable=SC2034,SC2154

# 3.1.2 Ensure wireless interfaces are not available.
# No wireless interface, or for every driver module of a wireless interface:
# not loadable (install ... /bin/true|false), not loaded, and deny listed.
cus_3_1_2() {
    local id=$1 m n
    local -a mods bad=() ok=()
    need modprobe lsmod || return
    _need_fact wireless_modules || { result "$id" ERROR "wireless interface list unavailable: $NEED_ERR"; return; }
    mapfile -t mods <"$FACT_FILE"
    if (( ${#mods[@]} == 0 )); then
        result "$id" PASS "the system has no wireless interfaces"
        return
    fi
    for m in "${mods[@]}"; do
        [[ -n $m ]] || continue
        n=${m//-/_}
        case ${MOD_INSTALL[$n]-} in
            /bin/true|/bin/false) ok+=("module $m is not loadable (install $n ${MOD_INSTALL[$n]})") ;;
            *) bad+=("module $m is loadable, expected 'install $n /bin/false' or /bin/true") ;;
        esac
        if [[ -n ${LSMOD[$n]+x} ]]; then bad+=("module $m is loaded"); else ok+=("module $m is not loaded"); fi
        if [[ -n ${MOD_BLACKLIST[$n]+x} ]]; then ok+=("module $m is deny listed"); else bad+=("module $m is not deny listed"); fi
    done
    if (( ${#bad[@]} )); then
        result "$id" FAIL "wireless interfaces use these driver modules: ${mods[*]}" "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "wireless driver modules ${mods[*]} are not loadable, not loaded and deny listed" "${ok[@]}"
    fi
}

man_ev_3_1_1() {
    if flag_get IPV6_ENABLED; then
        [[ $REPLY == 1 ]] && printf 'IPv6 is enabled\n' || printf 'IPv6 is not enabled\n'
    else
        printf 'IPv6 state could not be derived\n'
    fi
}

man_ev_3_2_7() {
    if need_kmod; then
        printf 'network modules available to the running kernel: %s\n' \
            "$(grep -c '/kernel/net/' "$FACTS_DIR/kmod_files")"
    fi
}
