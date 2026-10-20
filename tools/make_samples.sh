#!/usr/bin/env bash
# tools/make_samples.sh - sample reports in docs/samples/ from the offline fixtures.
# The fixtures are SYNTHETIC (see tests/README.md), so these samples show the report
# layout, not the result of a real machine.
set -u
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
out=$here/../docs/samples
rm -rf "$out"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
for n in fresh hardened; do
    exc=()
    if [[ $n == hardened ]]; then
        printf '2.1.19 | Host is the production web server (nginx on 80/443) | V. Hoeck | 2999-12-31\n' >"$tmp/exceptions.conf"
        exc=(--exceptions "$tmp/exceptions.conf")
    fi
    bash "$here/../tests/run_fixture.sh" "$n" --output "$tmp/$n" --no-color --quiet "${exc[@]}" >/dev/null 2>&1
    cp "$tmp/$n"/*.txt "$out/sample-$n-synthetic.txt"
    cp "$tmp/$n"/*.html "$out/sample-$n-synthetic.html"
done
printf 'wrote %s\n' "$out"
