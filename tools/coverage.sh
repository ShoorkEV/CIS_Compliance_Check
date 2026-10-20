#!/usr/bin/env bash
# tools/coverage.sh - catalog vs implemented functions vs benchmark IDs.
#
# usage: tools/coverage.sh [recs.json]
#   recs.json (from tools/parse.py) is optional; with it the catalog IDs are compared
#   with the IDs found in the benchmark PDF.
# Exit 0 only when: 350 catalog rows, 274 with srv_level=1, no Level 1 - Server row
# with status=todo, a chk_<type> function for every generic type, a cus_<id> function
# for every custom row, and (with recs.json) the same ID set as the PDF.
set -u
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$HERE/..
CAT=$ROOT/catalog/controls.tsv
fail=0
say() { printf '%s\n' "$*"; }
bad() { say "FAIL: $*"; fail=1; }

total=0 l1=0 l1todo=0 custom_missing=0 generic_missing=0 manual_nohint=0
declare -A types=()
while IFS=$'\t' read -r id title assess srv ws type params applies slow status; do
    [[ $id == id ]] && continue
    total=$((total + 1))
    if [[ $srv == 1 ]]; then
        l1=$((l1 + 1))
        [[ $status == todo ]] && { l1todo=$((l1todo + 1)); bad "Level 1 - Server row $id has status=todo"; }
        types[$type]=$((${types[$type]:-0} + 1))
        fn=${id//./_}
        case $type in
            custom)
                if ! grep -qE "^cus_${fn}\(\)" "$ROOT"/lib/checks_custom/*.sh; then
                    custom_missing=$((custom_missing + 1)); bad "no function cus_$fn for custom row $id"
                fi ;;
            manual)
                [[ $params == *hint=* ]] || { manual_nohint=$((manual_nohint + 1)); bad "manual row $id has no hint"; } ;;
            -) bad "Level 1 - Server row $id has no check type" ;;
            *)
                if ! grep -qE "^chk_${type}\(\)" "$ROOT"/lib/checks_generic.sh; then
                    generic_missing=$((generic_missing + 1)); bad "no function chk_$type for row $id"
                fi ;;
        esac
    fi
done <"$CAT"

say "catalog rows:                $total"
say "srv_level=1 rows:            $l1"
say "L1 Server rows with todo:    $l1todo"
say "custom rows w/o function:    $custom_missing"
say "generic rows w/o function:   $generic_missing"
say "check types (L1 Server):"
for t in $(printf '%s\n' "${!types[@]}" | sort); do printf '  %-26s %s\n' "$t" "${types[$t]}"; done
(( total == 350 )) || bad "expected 350 catalog rows, found $total"
(( l1 == 274 )) || bad "expected 274 Level 1 - Server rows, found $l1"

if [[ -n ${1-} ]]; then
    mapfile -t pdf_ids < <(grep -o '"id": "[^"]*"' "$1" | cut -d'"' -f4 | sort -u)
    mapfile -t cat_ids < <(cut -f1 "$CAT" | tail -n +2 | sort -u)
    say "benchmark IDs in $1:  ${#pdf_ids[@]}"
    only_pdf=$(comm -23 <(printf '%s\n' "${pdf_ids[@]}") <(printf '%s\n' "${cat_ids[@]}"))
    only_cat=$(comm -13 <(printf '%s\n' "${pdf_ids[@]}") <(printf '%s\n' "${cat_ids[@]}"))
    [[ -z $only_pdf ]] || bad "IDs in the PDF but not in the catalog: $only_pdf"
    [[ -z $only_cat ]] || bad "IDs in the catalog but not in the PDF: $only_cat"
fi
if (( fail )); then say "coverage: FAILED"; exit 1; fi
say "coverage: OK"
