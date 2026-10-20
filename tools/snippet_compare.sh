#!/usr/bin/env bash
# tools/snippet_compare.sh - compare the repaired PDF audit snippets with the script's
# state (plan section 12, oracle 2). TEST VMs ONLY: the snippets walk /var/log and the
# local filesystems.
#
#   sudo tools/snippet_compare.sh /path/to/cis-audit.sh
#
# Only the two snippets in tools/reference/ are repaired so far (6.1.3.1, 7.1.11). To add
# one: repair the PDF text (page footers, wrapped commands, merged continuations), save it as
# tools/reference/cis_<id>_audit.sh and add a line to SNIPPETS below with how to read its verdict.
set -u
(( EUID == 0 )) || { echo "run as root on a test VM" >&2; exit 3; }
AUDIT=${1:?usage: snippet_compare.sh /path/to/cis-audit.sh}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORK=$(mktemp -d /var/tmp/cis-snippets.XXXXXX)
trap 'rm -rf -- "$WORK"' EXIT

# id | verdict rule: "pf" = output contains ** PASS ** / ** FAIL **, "list" = FAIL when a list of files is printed
SNIPPETS=(
    "6.1.3.1|pf"
    "7.1.11|list"
)
bash "$AUDIT" --quiet --format text --output "$WORK/out" >/dev/null 2>&1
report=$(ls -t "$WORK"/out/*.txt | head -n1)
rc=0
for s in "${SNIPPETS[@]}"; do
    IFS='|' read -r id rule <<<"$s"
    out=$(bash "$HERE/reference/cis_${id}_audit.sh" 2>&1)
    case $rule in
        pf) [[ $out == *"** PASS **"* ]] && snip=PASS || snip=FAIL ;;
        list) if grep -qE 'World writable (files|directories)|list of World writable' <<<"$out"; then snip=FAIL; else snip=PASS; fi ;;
    esac
    mine=$(sed -n '/^5. FULL RESULTS/,$p' "$report" | grep -m1 -E "^\[[A-Z/]+\] $id " | sed -E 's/^\[([A-Z/]+)\].*/\1/')
    printf '%-8s snippet=%-5s script=%-8s %s\n' "$id" "$snip" "$mine" "$([[ $snip == "$mine" ]] && echo match || echo MISMATCH)"
    [[ $snip == "$mine" ]] || rc=1
done
exit "$rc"
