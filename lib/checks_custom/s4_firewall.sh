#!/usr/bin/env bash
# lib/checks_custom/s4_firewall.sh - custom checks, benchmark section 4 (ufw).
# shellcheck disable=SC2034,SC2154

# 4.1.2 Ensure ufw service is configured: ufw.service enabled and active, and
# `ufw status` reports "Status: active".
cus_4_1_2() {
    local id=$1 status
    local -a bad=() ok=()
    need units || return
    unit_describe ufw.service
    if unit_is_enabled ufw.service && unit_is_active ufw.service; then
        ok+=("ufw.service: $REPLY (enabled/active)")
    else
        bad+=("ufw.service: $REPLY (enabled-state/active-state), expected enabled and active")
    fi
    if fact ufw_status; then
        status=$(grep -Pm1 -- '^Status:' "$FACT_FILE")
        if [[ $status == "Status: active" ]]; then ok+=("ufw status: $status"); else bad+=("ufw status: ${status:-no status line}, expected 'Status: active'"); fi
    else
        bad+=("ufw status could not be read (ufw not installed?)")
    fi
    if (( ${#bad[@]} )); then
        result "$id" FAIL "${bad[@]}" "${ok[@]}"
    else
        result "$id" PASS "${ok[@]}"
    fi
}

# ufw_default <direction> -> REPLY: policy word from "Default: deny (incoming), ..."
ufw_default() {
    REPLY=$(grep -Pm1 -- '^Default:' "$FACT_FILE" | grep -Po "[a-z]+(?= \($1\))" | head -n1)
}

# 4.1.3 Ensure ufw incoming default is configured: deny or reject.
cus_4_1_3() {
    local id=$1 pol
    if ! fact ufw_status; then
        result "$id" FAIL "ufw status verbose could not be read (ufw not installed?), expected 'Default: deny (incoming)'"
        return
    fi
    ufw_default incoming
    pol=$REPLY
    if [[ -z $pol ]]; then
        result "$id" FAIL "ufw reports no default policies (ufw is probably inactive), expected 'Default: deny (incoming)'" \
            "ufw status: $(grep -m1 '^Status:' "$FACT_FILE")"
    elif [[ $pol == deny || $pol == reject ]]; then
        result "$id" PASS "ufw default policy for incoming: $pol, expected deny or reject"
    else
        result "$id" FAIL "ufw default policy for incoming: $pol, expected deny or reject"
    fi
}

# 4.1.5 Ensure ufw routed default is configured: deny. When forwarding is off in the
# kernel, ufw prints "disabled (routed)"; then DEFAULT_FORWARD_POLICY in
# /etc/default/ufw is read, as the PDF's note says.
cus_4_1_5() {
    local id=$1 pol cfg
    if ! fact ufw_status; then
        result "$id" FAIL "ufw status verbose could not be read (ufw not installed?), expected 'deny (routed)'"
        return
    fi
    ufw_default routed
    pol=$REPLY
    case $pol in
        deny)
            result "$id" PASS "ufw default policy for routed: deny" ;;
        disabled)
            cfg=$(grep -Pi -- '^\s*DEFAULT_FORWARD_POLICY\s*=' "$R/etc/default/ufw" 2>/dev/null | tail -n1)
            if [[ ${cfg,,} =~ =[[:space:]]*\"?drop\"? ]]; then
                result "$id" PASS "ufw shows 'disabled (routed)' because kernel forwarding is off" "/etc/default/ufw: $cfg (DROP means deny)"
            else
                result "$id" FAIL "ufw shows 'disabled (routed)' because kernel forwarding is off" "/etc/default/ufw: ${cfg:-DEFAULT_FORWARD_POLICY not found}, expected DROP"
            fi ;;
        '')
            result "$id" FAIL "ufw reports no default policies (ufw is probably inactive), expected 'deny (routed)'" ;;
        *)
            result "$id" FAIL "ufw default policy for routed: $pol, expected deny" ;;
    esac
}
