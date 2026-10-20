#!/usr/bin/env bash
# lib/report_html.sh - the self-contained HTML report.
# One file: inline CSS and plain JavaScript, no external fonts, CDNs or images.
# Every value taken from the host goes through html_escape (one helper, core.sh).
# shellcheck disable=SC2034

# esc <string>: E = html-escaped string (no subshell)
esc() { html_escape "$1"; E=$REPLY; }

html_style() {
    cat <<'CSS'
:root{--bg:#fff;--fg:#1d2330;--mut:#5b6475;--bd:#d6dae3;--card:#f5f6f9;--pass:#1a7f37;--fail:#c4262e;--exc:#8250df;--man:#b36b00;--na:#6e7781;--skip:#6e7781;--err:#c4262e}
@media (prefers-color-scheme:dark){:root{--bg:#14171d;--fg:#e4e7ee;--mut:#98a1b3;--bd:#30363f;--card:#1c2028;--pass:#3fb950;--fail:#ff6b6b;--exc:#b392f0;--man:#e3a53a;--na:#9aa3b2;--skip:#9aa3b2;--err:#ff6b6b}}
*{box-sizing:border-box}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto}
h1{font-size:1.4rem;margin:.2rem 0 .6rem}h2{font-size:1.1rem;margin:1.6rem 0 .5rem;border-bottom:1px solid var(--bd);padding-bottom:.2rem}
table{border-collapse:collapse;width:100%;margin:.4rem 0}th,td{border:1px solid var(--bd);padding:.3rem .5rem;text-align:left;vertical-align:top}th{background:var(--card)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.meta td:first-child{width:14rem;color:var(--mut)}
.cards{display:flex;flex-wrap:wrap;gap:.5rem;margin:.6rem 0}.card{background:var(--card);border:1px solid var(--bd);border-radius:6px;padding:.4rem .8rem;min-width:7rem}
.card b{display:block;font-size:1.3rem}
.tools{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;margin:.6rem 0}
button,input{font:inherit;color:inherit;background:var(--card);border:1px solid var(--bd);border-radius:4px;padding:.25rem .6rem}
button.on{outline:2px solid var(--fg)}input{min-width:14rem}
.ctl{border:1px solid var(--bd);border-radius:6px;margin:.35rem 0;background:var(--card)}
.ctl>summary{cursor:pointer;padding:.35rem .6rem;list-style:none}
.ctl>summary::-webkit-details-marker{display:none}
.st{display:inline-block;min-width:5.6rem;font-weight:700;font-size:.85rem}
.s-PASS .st{color:var(--pass)}.s-FAIL .st,.s-ERROR .st{color:var(--fail)}.s-EXCEPTION .st{color:var(--exc)}.s-MANUAL .st{color:var(--man)}.s-NA .st,.s-SKIPPED .st{color:var(--na)}
.id{font-family:ui-monospace,Consolas,monospace;margin-right:.5rem}
.ev{margin:0;padding:.3rem .8rem .6rem 2rem}.ev li{margin:.1rem 0;word-break:break-word;white-space:pre-wrap}
.note{color:var(--mut);font-style:italic}
.hide{display:none}
@media print{.tools{display:none}.ctl{break-inside:avoid}.ctl>summary{display:block}details.ctl:not([open])>*:not(summary){display:block}body{background:#fff;color:#000}}
CSS
}

html_script() {
    cat <<'JS'
(function(){
var btns=document.querySelectorAll('[data-filter]'),q=document.getElementById('q'),
    ctls=document.querySelectorAll('#full .ctl'),active={};
function apply(){var any=Object.keys(active).length,t=(q.value||'').toLowerCase();
 ctls.forEach(function(c){var ok=(!any||active[c.getAttribute('data-state')]),
  h=c.querySelector('summary').textContent.toLowerCase();
  c.classList.toggle('hide',!(ok&&(!t||h.indexOf(t)>-1)));});}
btns.forEach(function(b){b.addEventListener('click',function(){var s=b.getAttribute('data-filter');
 if(s==='ALL'){active={};btns.forEach(function(x){x.classList.remove('on')});}
 else{if(active[s]){delete active[s];b.classList.remove('on');}else{active[s]=1;b.classList.add('on');}}
 apply();});});
q.addEventListener('input',apply);
document.getElementById('expand').addEventListener('click',function(){ctls.forEach(function(c){c.open=true})});
document.getElementById('collapse').addEventListener('click',function(){ctls.forEach(function(c){c.open=false})});
})();
JS
}

html_control() { # html_control <id> <open|"">
    local id=$1 st=${R_STATE[$1]} line cls est eid etitle
    cls=${st//\//}
    esc "$st"; est=$E
    esc "$id"; eid=$E
    sanitize "${CAT_TITLE[$id]}"; esc "$REPLY"; etitle=$E
    printf '<details class="ctl s-%s" data-state="%s"%s><summary><span class="st">%s</span><span class="id">%s</span>%s</summary>\n<ul class="ev">\n' \
        "$cls" "$cls" "${2:+ open}" "$est" "$eid" "$etitle"
    sanitize "${R_EVID[$id]}"
    local ev=$REPLY
    while IFS= read -r line; do
        if [[ -n $line ]]; then esc "$line"; printf '<li>%s</li>\n' "$E"; fi
    done <<<"$ev"
    if [[ -n ${R_NOTE[$id]-} ]]; then
        sanitize "${R_NOTE[$id]}"; esc "$REPLY"
        printf '<li class="note">%s</li>\n' "$E"
    fi
    printf '</ul></details>\n'
}

report_html() {
    local out=$1 id s sec left flag any k v e1 e2 e3 e4 e5
    {
        esc "$HOST_NAME"
        printf '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
        printf '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        printf '<title>CIS audit %s</title>\n<style>\n' "$E"
        html_style
        printf '</style></head><body><main>\n'
        esc "$CIS_BENCH_NAME"; e1=$E
        esc "$CIS_BENCH_VERSION"; e2=$E
        esc "$LEVEL"; e3=$E
        esc "$PROFILE_LABEL"; e4=$E
        printf '<h1>%s %s &ndash; Level %s %s audit</h1>\n' "$e1" "$e2" "$e3" "$e4"
        printf '<p class="note">Internal compliance check, not an official CIS-CAT result.</p>\n'

        printf '<h2>Run</h2>\n<table class="meta">\n'
        while IFS='|' read -r k v; do
            esc "$k"; e1=$E
            esc "$v"; e2=$E
            printf '<tr><td>%s</td><td>%s</td></tr>\n' "$e1" "$e2"
        done <<EOF
Host|$HOST_NAME
FQDN|$HOST_FQDN
OS release|$OS_PRETTY
Kernel|$KERNEL
Run started|$RUN_START
Run finished|$RUN_END
Duration|${RUN_SECONDS}s
Benchmark|$CIS_BENCH_NAME $CIS_BENCH_VERSION
Profile / level|$PROFILE_LABEL / Level $LEVEL (cumulative)
Script version|cis-audit $CIS_VERSION
Catalog SHA-256|$SHA_CATALOG
site.conf SHA-256|$SHA_SITE
exceptions.conf SHA-256|$SHA_EXC
Options|$OPTS_GIVEN
EOF
        printf '</table>\n'

        printf '<h2>Summary</h2>\n<div class="cards">\n'
        for s in "${REPORT_STATES[@]}"; do
            esc "$s"
            printf '<div class="card"><b>%s</b>%s</div>\n' "${CNT[$s]}" "$E"
        done
        esc "$SCORE_ALL"
        printf '<div class="card"><b>%s</b>Score (PASS / (PASS + FAIL))</div>\n</div>\n' "$E"
        printf '<table><thead><tr><th>Section</th><th class="n">PASS</th><th class="n">FAIL</th><th class="n">EXCEPTION</th><th class="n">MANUAL</th><th class="n">N/A</th><th class="n">SKIPPED</th><th class="n">ERROR</th><th class="n">Score</th></tr></thead><tbody>\n'
        for sec in 1 2 3 4 5 6 7; do
            [[ -n ${SCNT[$sec:total]+x} ]] || continue
            score_str "${SCNT[$sec:PASS]:-0}" "${SCNT[$sec:FAIL]:-0}"
            esc "$REPLY"; e2=$E
            esc "${SECTION_NAMES[$sec]}"; e1=$E
            printf '<tr><td>%s %s</td>' "$sec" "$e1"
            for s in "${REPORT_STATES[@]}"; do printf '<td class="n">%s</td>' "${SCNT[$sec:$s]:-0}"; done
            printf '<td class="n">%s</td></tr>\n' "$e2"
        done
        printf '</tbody></table>\n'

        printf '<h2>Findings (FAIL and ERROR)</h2>\n'
        any=0
        for id in "${RUN_IDS[@]}"; do
            [[ ${R_STATE[$id]} == FAIL || ${R_STATE[$id]} == ERROR ]] || continue
            any=1
            html_control "$id" open
        done
        (( any )) || printf '<p>none</p>\n'

        printf '<h2>Manual review</h2>\n'
        any=0
        for id in "${RUN_IDS[@]}"; do
            [[ ${R_STATE[$id]} == MANUAL ]] || continue
            any=1
            html_control "$id" ""
        done
        (( any )) || printf '<p>none</p>\n'

        printf '<h2>Exceptions</h2>\n'
        if (( ${#EXC_JUST[@]} )); then
            printf '<table><thead><tr><th>ID</th><th>State</th><th>Justification</th><th>Approved by</th><th>Expires</th><th>Days left</th></tr></thead><tbody>\n'
            for id in $(printf '%s\n' "${!EXC_JUST[@]}" | sort_ids); do
                days_left "${EXC_EXP[$id]}"
                left=$REPLY
                flag=$left
                (( left < 0 )) && flag="EXPIRED ($left)"
                sanitize "${EXC_JUST[$id]}"; esc "$REPLY"; e3=$E
                esc "$id"; e1=$E
                esc "${R_STATE[$id]:-not run}"; e2=$E
                esc "${EXC_BY[$id]}"; e4=$E
                esc "${EXC_EXP[$id]}"; e5=$E
                printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>' "$e1" "$e2" "$e3" "$e4" "$e5"
                esc "$flag"
                printf '<td>%s</td></tr>\n' "$E"
            done
            printf '</tbody></table>\n'
        else
            printf '<p>none</p>\n'
        fi

        printf '<h2>Full results</h2>\n<div class="tools">\n<button data-filter="ALL">All</button>\n'
        for s in "${REPORT_STATES[@]}"; do
            esc "$s"
            printf '<button data-filter="%s">%s</button>\n' "${s//\//}" "$E"
        done
        printf '<input id="q" type="search" placeholder="Search ID or title" aria-label="Search ID or title">\n'
        printf '<button id="expand">Expand all</button><button id="collapse">Collapse all</button>\n</div>\n<div id="full">\n'
        for id in "${RUN_IDS[@]}"; do
            html_control "$id" ""
        done
        printf '</div>\n<script>\n'
        html_script
        printf '</script>\n</main></body></html>\n'
    } >"$out"
}
