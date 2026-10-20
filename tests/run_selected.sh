#!/usr/bin/env bash
# tests/run_selected.sh - run some tests of the bats files through runbats.sh.
# usage: tests/run_selected.sh <file.bats>:<name filter> ...   (use "file.bats:" for all tests of a file)
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
rc=0
for spec in "$@"; do
    file=${spec%%:*}
    filter=${spec#*:}
    if [[ -n $filter ]]; then
        bash "$here/runbats.sh" -f "$filter" "$here/unit/$file" || rc=1
    else
        bash "$here/runbats.sh" "$here/unit/$file" || rc=1
    fi
done
exit "$rc"
