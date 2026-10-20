#!/usr/bin/env bash
# tests/gen_golden_candidates.sh - run the audit on each fixture and write the result table
# (id<TAB>state) to <outdir>/<fixture>.tsv. The output is a CANDIDATE for tests/expected/*.tsv:
# review every line against the benchmark's Audit text before copying it over.
#
# usage: tests/gen_golden_candidates.sh <outdir>
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
out=${1:?usage: gen_golden_candidates.sh <outdir>}
mkdir -p "$out"
for n in hardened fresh variant; do
    rep=$out/reports_$n
    rm -rf "$rep"
    mkdir -p "$rep"
    exc=()
    if [[ $n == hardened ]]; then
        printf '2.1.19 | nginx web server on 80/443 | V. Hoeck | 2999-12-31\n' >"$out/exceptions.conf"
        exc=(--exceptions "$out/exceptions.conf")
    fi
    bash "$here/run_fixture.sh" "$n" --output "$rep" --format text --no-color --quiet "${exc[@]}" >"$rep/stdout" 2>&1
    echo "rc=$?" >>"$rep/stdout"
    f=$(ls "$rep"/*.txt | head -n1)
    sed -n '/^5. FULL RESULTS/,$p' "$f" | grep -E '^\[[A-Z/]+\] [0-9]' |
        sed -E 's/^\[([A-Z/]+)\] ([0-9.]+) .*/\2\t\1/' |
        LC_ALL=C sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -k5,5n >"$out/$n.tsv"
done
echo finished >"$out/done"
