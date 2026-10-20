#!/usr/bin/env bash
# lib/exceptions.sh - site.conf and exceptions.conf parsing and exception handling.
#
# Both files are parsed line by line as data. They are never sourced or eval'ed:
# the script runs as root. Unknown keys, bad syntax, values weaker than the
# benchmark, or an exception for an unknown control stop the run with exit code 3,
# so a typo cannot silently weaken the audit.
# shellcheck disable=SC2034

# key -> rule. Benchmark values are copied from the PDF; the control ID is the
# place to verify them (also cited in etc/site.conf.example).
declare -A SITE_RULE=(
    [BANNER_FILE]="path"
    [TIME_DAEMON]="enum:auto,chrony,timesyncd"
    [LOGGER]="enum:auto,journald,rsyslog"
    [APPROVED_LISTENERS]="text"
    [APPROVED_SUID_FILE]="path"
    [SSH_ALLOW_DIRECTIVE_REQUIRED]="enum:1"        # 5.1.5
    [PASS_MAX_DAYS]="max:365:1"                    # 5.4.1.1
    [PASS_WARN_AGE]="min:7"                        # 5.4.1.3
    [INACTIVE]="max:45:0"                          # 5.4.1.5
    [PWQ_MINLEN]="min:14"                          # 5.3.3.2.2
    [PWQ_DIFOK]="min:2"                            # 5.3.3.2.1
    [FAILLOCK_DENY]="max:5:1"                      # 5.3.3.1.1
    [FAILLOCK_UNLOCK_TIME]="zmin:900"              # 5.3.3.1.2
    [PWHISTORY_REMEMBER]="min:24"                  # 5.3.3.3.1
    [TMOUT_MAX]="max:900:1"                        # 5.4.3.2
    [SSH_MAX_AUTH_TRIES]="max:4:1"                 # 5.1.18
    [SSH_MAX_SESSIONS]="max:10:1"                  # 5.1.19
    [SSH_LOGIN_GRACE_TIME]="max:60:1"              # 5.1.15
)

site_load() {
    local file=$1 line n=0 key val rule
    [[ -r $file ]] || die_usage "site configuration $file is not readable"
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%$'\r'}
        trim "$line"
        line=$REPLY
        [[ -z $line || $line == \#* ]] && continue
        if [[ ! $line =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
            die_usage "$file:$n: syntax error (expected KEY=value)"
        fi
        key=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
        val=${val%%[[:space:]]#*}            # inline comment
        trim "$val"
        val=$REPLY
        val=${val#\"}
        val=${val%\"}
        if [[ -z ${SITE_RULE[$key]+x} ]]; then
            die_usage "$file:$n: unknown key $key"
        fi
        rule=${SITE_RULE[$key]}
        case $rule in
            path)
                [[ $val == /* ]] || die_usage "$file:$n: $key must be an absolute path" ;;
            text) ;;
            enum:*)
                list_has "${rule#enum:}" "$val" || die_usage "$file:$n: $key must be one of ${rule#enum:} (got '$val')" ;;
            max:*)
                is_uint "$val" || die_usage "$file:$n: $key must be a number"
                local mx=${rule#max:} mn
                mn=${mx#*:} mx=${mx%%:*}
                (( val >= mn )) || die_usage "$file:$n: $key=$val is below the minimum $mn"
                (( val <= mx )) || die_usage "$file:$n: $key=$val is weaker than the benchmark value $mx; record an accepted deviation in the exceptions file instead" ;;
            min:*)
                is_uint "$val" || die_usage "$file:$n: $key must be a number"
                (( val >= ${rule#min:} )) || die_usage "$file:$n: $key=$val is weaker than the benchmark value ${rule#min:}; record an accepted deviation in the exceptions file instead" ;;
            zmin:*)
                is_uint "$val" || die_usage "$file:$n: $key must be a number"
                (( val == 0 || val >= ${rule#zmin:} )) || die_usage "$file:$n: $key=$val is weaker than the benchmark value ${rule#zmin:} (0 means never); record an accepted deviation in the exceptions file instead" ;;
        esac
        SITE[$key]=$val
    done <"$file"
}

# exceptions_load <file>; ids are validated against the full catalog.
exceptions_load() {
    local file=$1 line n=0 id just by exp
    [[ -r $file ]] || die_usage "exceptions file $file is not readable"
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%$'\r'}
        trim "$line"
        line=$REPLY
        [[ -z $line || $line == \#* ]] && continue
        local bars=${line//[^|]/}
        (( ${#bars} == 3 )) || die_usage "$file:$n: expected exactly 3 '|' separators (no '|' inside the text)"
        IFS='|' read -r id just by exp <<<"$line"
        trim "$id";   id=$REPLY
        trim "$just"; just=$REPLY
        trim "$by";   by=$REPLY
        trim "$exp";  exp=$REPLY
        if [[ -z $id || -z $just || -z $by || -z $exp ]] || [[ $line != *'|'*'|'*'|'* ]]; then
            die_usage "$file:$n: expected 'id | justification | approved_by | expires (YYYY-MM-DD)'"
        fi
        if [[ -z ${CAT_TYPE[$id]+x} ]]; then
            die_usage "$file:$n: control $id is not in the catalog"
        fi
        valid_date "$exp" || die_usage "$file:$n: '$exp' is not a valid date (YYYY-MM-DD)"
        if [[ -n ${EXC_JUST[$id]+x} ]]; then
            die_usage "$file:$n: duplicate exception for $id"
        fi
        EXC_JUST[$id]=$just EXC_BY[$id]=$by EXC_EXP[$id]=$exp
    done <"$file"
}

# days_left <YYYY-MM-DD> -> REPLY (negative when expired)
days_left() {
    local d=$1 y m dd t
    y=${d:0:4} m=${d:5:2} dd=${d:8:2}
    days_from_civil "$y" "$m" "$dd"
    t=$REPLY
    days_from_civil "${TODAY:0:4}" "${TODAY:5:2}" "${TODAY:8:2}"
    REPLY=$((t - REPLY))
}

# Exceptions only ever turn FAIL into EXCEPTION. ERROR and MANUAL stay as they are.
exceptions_apply() {
    local id left
    for id in "${!EXC_JUST[@]}"; do
        [[ -n ${R_STATE[$id]+x} ]] || continue          # control not part of this run
        days_left "${EXC_EXP[$id]}"
        left=$REPLY
        case ${R_STATE[$id]} in
            FAIL)
                if (( left >= 0 )); then
                    R_STATE[$id]=EXCEPTION
                    R_NOTE[$id]="exception: ${EXC_JUST[$id]} (approved by ${EXC_BY[$id]}, expires ${EXC_EXP[$id]}, $left days left)"
                else
                    R_NOTE[$id]="exception expired on ${EXC_EXP[$id]} (${EXC_JUST[$id]}, approved by ${EXC_BY[$id]})"
                fi
                ;;
            PASS)
                R_NOTE[$id]="exception no longer needed (${EXC_JUST[$id]})"
                ;;
        esac
    done
}
