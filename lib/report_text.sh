#!/usr/bin/env bash
# lib/report_text.sh - report model (counts, scores, header data) and the text report.
# The text report is plain ASCII, 100 columns, one line per control, no colour codes.
# shellcheck disable=SC2034

declare -A CNT=() SCNT=()
SECTION_NAMES=([1]="Initial Setup" [2]="Services" [3]="Network" [4]="Host Based Firewall"
    [5]="Access, Authentication and Authorization" [6]="Logging and Auditing" [7]="System Maintenance")
REPORT_STATES=(PASS FAIL EXCEPTION MANUAL N/A SKIPPED ERROR)

# score_str <pass> <fail> -> REPLY like "93.4%" or "n/a"
score_str() {
    local p=$1 f=$2 den=$(($1 + $2)) t
    if (( den == 0 )); then REPLY="n/a"; return; fi
    t=$(( p * 1000 / den ))
    REPLY="$((t / 10)).$((t % 10))%"
}

report_prepare() {
    local id st sec s
    CNT=() SCNT=()
    for s in "${REPORT_STATES[@]}"; do CNT[$s]=0; done
    for id in "${RUN_IDS[@]}"; do
        st=${R_STATE[$id]}
        sec=${id%%.*}
        CNT[$st]=$((CNT[$st] + 1))
        SCNT[$sec:$st]=$(( ${SCNT[$sec:$st]:-0} + 1 ))
        SCNT[$sec:total]=$(( ${SCNT[$sec:total]:-0} + 1 ))
    done
    score_str "${CNT[PASS]}" "${CNT[FAIL]}"
    SCORE_ALL=$REPLY
}

# wrap_lines <width> <first-prefix> <next-prefix> <text>  -> prints wrapped lines
wrap_lines() {
    local width=$1 p1=$2 p2=$3 text=$4 line="" word prefix=$2 room
    local -a words
    read -ra words <<<"$text"
    if (( ${#words[@]} == 0 )); then printf '%s\n' "$p1"; return; fi
    for word in "${words[@]}"; do
        room=$((width - ${#prefix}))
        while (( ${#word} > room )); do
            if [[ -n $line ]]; then
                printf '%s%s\n' "$prefix" "$line"
                line="" prefix=$p2 room=$((width - ${#p2}))
            else
                printf '%s%s\n' "$prefix" "${word:0:room}"
                word=${word:room} prefix=$p2 room=$((width - ${#p2}))
            fi
        done
        if [[ -z $line ]]; then
            line=$word
        elif (( ${#line} + 1 + ${#word} <= room )); then
            line+=" $word"
        else
            printf '%s%s\n' "$prefix" "$line"
            prefix=$p2
            line=$word
        fi
    done
    [[ -n $line ]] && printf '%s%s\n' "$prefix" "$line"
}

text_control_block() { # one control: result line + wrapped evidence
    local id=$1 ev line t
    sanitize "${CAT_TITLE[$id]}"
    t=$REPLY
    trunc "[${R_STATE[$id]}] $id $t" 100
    printf '%s\n' "$REPLY"
    sanitize "${R_EVID[$id]}"
    ev=$REPLY
    while IFS= read -r line; do
        [[ -n $line ]] && wrap_lines 100 "    - " "      " "$line"
    done <<<"$ev"
    if [[ -n ${R_NOTE[$id]-} ]]; then
        sanitize "${R_NOTE[$id]}"
        wrap_lines 100 "    * " "      " "$REPLY"
    fi
}

report_text() {
    local out=$1 id s sec rule
    rule=$(printf '%0.s=' {1..100})
    {
        printf '%s\n' "$rule"
        printf '%s\n' "$CIS_BENCH_NAME $CIS_BENCH_VERSION - Level $LEVEL $PROFILE_LABEL audit report"
        printf '%s\n\n' "$rule"
        printf '%-22s %s\n' \
            "Host:" "$HOST_NAME" "FQDN:" "$HOST_FQDN" "OS release:" "$OS_PRETTY" "Kernel:" "$KERNEL" \
            "Run started:" "$RUN_START" "Run finished:" "$RUN_END" "Duration:" "${RUN_SECONDS}s" \
            "Benchmark:" "$CIS_BENCH_NAME $CIS_BENCH_VERSION" "Profile / level:" "$PROFILE_LABEL / Level $LEVEL (cumulative)" \
            "Script version:" "cis-audit $CIS_VERSION" "Catalog SHA-256:" "$SHA_CATALOG" \
            "site.conf SHA-256:" "$SHA_SITE" "exceptions.conf SHA-256:" "$SHA_EXC" "Options:" "$OPTS_GIVEN"
        printf '\nInternal compliance check, not an official CIS-CAT result.\n\n'

        printf '%s\n' "1. SUMMARY" "----------"
        for s in "${REPORT_STATES[@]}"; do printf '  %-10s %5d\n' "$s" "${CNT[$s]}"; done
        printf '  %-10s %s   (PASS / (PASS + FAIL))\n\n' "SCORE" "$SCORE_ALL"
        printf '  %-4s %-42s %5s %5s %5s %5s %5s %7s\n' Sec Section PASS FAIL MAN. N/A OTHER SCORE
        for sec in 1 2 3 4 5 6 7; do
            [[ -n ${SCNT[$sec:total]+x} ]] || continue
            score_str "${SCNT[$sec:PASS]:-0}" "${SCNT[$sec:FAIL]:-0}"
            printf '  %-4s %-42s %5d %5d %5d %5d %5d %7s\n' "$sec" "${SECTION_NAMES[$sec]}" \
                "${SCNT[$sec:PASS]:-0}" "${SCNT[$sec:FAIL]:-0}" "${SCNT[$sec:MANUAL]:-0}" "${SCNT[$sec:N/A]:-0}" \
                "$(( ${SCNT[$sec:total]} - ${SCNT[$sec:PASS]:-0} - ${SCNT[$sec:FAIL]:-0} - ${SCNT[$sec:MANUAL]:-0} - ${SCNT[$sec:N/A]:-0} ))" "$REPLY"
        done

        printf '\n%s\n' "2. FINDINGS (FAIL and ERROR)" "----------------------------"
        local any=0
        for id in "${RUN_IDS[@]}"; do
            [[ ${R_STATE[$id]} == FAIL || ${R_STATE[$id]} == ERROR ]] || continue
            any=1
            text_control_block "$id"
        done
        (( any )) || printf '  none\n'

        printf '\n%s\n' "3. MANUAL REVIEW" "----------------"
        any=0
        for id in "${RUN_IDS[@]}"; do
            [[ ${R_STATE[$id]} == MANUAL ]] || continue
            any=1
            text_control_block "$id"
        done
        (( any )) || printf '  none\n'

        printf '\n%s\n' "4. EXCEPTIONS" "-------------"
        any=0
        local left flag
        for id in $(printf '%s\n' "${!EXC_JUST[@]}" | sort_ids); do
            any=1
            days_left "${EXC_EXP[$id]}"
            left=$REPLY
            flag="$left days left"
            (( left < 0 )) && flag="EXPIRED $((-left)) days ago"
            sanitize "${EXC_JUST[$id]}"
            printf '  %s  state=%s  approved by %s  expires %s (%s)\n' "$id" "${R_STATE[$id]:-not-run}" "${EXC_BY[$id]}" "${EXC_EXP[$id]}" "$flag"
            wrap_lines 100 "      " "      " "$REPLY"
        done
        (( any )) || printf '  none\n'

        printf '\n%s\n' "5. FULL RESULTS" "---------------"
        for id in "${RUN_IDS[@]}"; do
            text_control_block "$id"
        done
    } >"$out"
}
