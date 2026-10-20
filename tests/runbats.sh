#!/usr/bin/env bash
# tests/runbats.sh - tiny runner for the .bats files when bats itself is not installed.
#
# Supports the subset the tests use: @test "name" { ... }, setup, teardown, load,
# run (sets $status, $output, ${lines[@]}), skip, BATS_TEST_DIRNAME, BATS_TEST_TMPDIR.
# CI uses the real bats; this exists so the suite also runs on a dev box without it.
#
# usage: tests/runbats.sh [-f pattern] file.bats...
set -u
pattern=""
if [[ ${1-} == -f ]]; then pattern=$2; shift 2; fi
pass=0 fail=0 skipped=0
failed=()

skip() { echo "SKIP: ${*:-}"; exit 77; }
run() {
    local out
    status=0
    out=$("$@" 2>&1) || status=$?
    output=$out
    mapfile -t lines <<<"$out"
    return 0
}
load() { source "$BATS_TEST_DIRNAME/$1.bash"; }

for file in "$@"; do
    unset -f setup teardown 2>/dev/null
    BATS_TEST_DIRNAME=$(cd -- "$(dirname -- "$file")" && pwd)
    names=()
    n=0
    src=""
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ $line =~ ^@test[[:space:]]+\"(.*)\"[[:space:]]*\{[[:space:]]*$ ]]; then
            n=$((n + 1))
            names[$n]=${BASH_REMATCH[1]}
            src+="bats_test_$n() {"$'\n'
        else
            src+="$line"$'\n'
        fi
    done <"$file"
    # shellcheck disable=SC1090
    source <(printf '%s' "$src")
    for ((i = 1; i <= n; i++)); do
        name=${names[$i]}
        [[ -n $pattern && $name != *$pattern* ]] && continue
        tmp=$(mktemp -d)
        log=$tmp/log
        (
            export BATS_TEST_TMPDIR=$tmp BATS_TEST_DIRNAME
            set -eE
            declare -F setup >/dev/null && setup
            "bats_test_$i"
        ) >"$log" 2>&1
        rc=$?
        if [[ $rc -eq 0 ]]; then
            pass=$((pass + 1))
            printf 'ok   %s - %s\n' "$(basename "$file")" "$name"
        elif [[ $rc -eq 77 ]]; then
            skipped=$((skipped + 1))
            printf 'skip %s - %s\n' "$(basename "$file")" "$name"
        else
            fail=$((fail + 1))
            failed+=("$(basename "$file"): $name")
            printf 'FAIL %s - %s\n' "$(basename "$file")" "$name"
            sed 's/^/     | /' "$log" | head -n 25
        fi
        rm -rf "$tmp"
    done
done
printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
(( fail == 0 ))
