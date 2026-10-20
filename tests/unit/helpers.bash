# tests/helpers.bash - shared helpers for the bats tests (load helpers).
# Tests copy a recorded fixture into a temp dir, mutate it, and run the audit offline
# against it (CIS_AUDIT_TESTMODE / CIS_AUDIT_FACTS_DIR / CIS_AUDIT_ROOTFS).

ROOT_DIR="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
FIXTURES="$ROOT_DIR/tests/fixtures"
AUDIT="$ROOT_DIR/cis-audit.sh"
[ -n "${CIS_AUDIT_UNDER_TEST:-}" ] && AUDIT="$CIS_AUDIT_UNDER_TEST"

# fx <fixture>: copy a fixture into the test's temp dir; sets FX, FACTS, RFS, OUT
fx() {
    FX="$BATS_TEST_TMPDIR/fx"
    rm -rf "$FX"
    cp -r "$FIXTURES/$1" "$FX"
    FACTS="$FX/facts"
    RFS="$FX/rootfs"
    OUT="$BATS_TEST_TMPDIR/out"
    rm -rf "$OUT"
}

# audit [cis-audit options]: run the script against the current fixture; sets $status/$output
audit() {
    CIS_AUDIT_TESTMODE=1 CIS_AUDIT_FACTS_DIR="$FACTS" CIS_AUDIT_ROOTFS="$RFS" \
        run bash "$AUDIT" --output "$OUT" --no-color --format text "$@"
}

# check <id> [options]: audit exactly one control
check() {
    local id=$1
    shift
    audit --only "$id" "$@"
}

# report: path of the newest text report
report() { ls -t "$OUT"/*.txt 2>/dev/null | head -n1; }

# state_of <id>: the state of a control in the newest report
state_of() {
    grep -m1 -E "^\[[A-Z/]+\] $1 " "$(report)" | sed -E 's/^\[([A-Z/]+)\].*/\1/'
}

# evidence_of <id>: indented evidence lines below the control line (full results section)
evidence_of() {
    awk -v id="$1" '
        $0 ~ "^\\[[A-Z/]+\\] " id " " { found = 1; next }
        found && /^    / { print; next }
        found { exit }
    ' "$(report)"
}

# assert_state <id> <STATE>
assert_state() {
    local got
    got=$(state_of "$1")
    if [ "$got" != "$2" ]; then
        echo "expected $1 to be $2 but it is '$got'"
        evidence_of "$1"
        return 1
    fi
}

# sset <path> <mode> <user> <group> [type]: set or replace file metadata in the fixture
sset() {
    local tmp
    tmp=$(grep -vP "^\\Q$1\\E\t" "$FACTS/stat.tsv" || true)
    printf '%s\n' "$tmp" >"$FACTS/stat.tsv"
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-f}" >>"$FACTS/stat.tsv"
}

# put <file under the fixture> with stdin
put() {
    mkdir -p "$(dirname "$1")"
    cat >"$1"
}

# results_table: "id<TAB>state" for every control of the newest report, sorted
results_table() {
    sed -n '/^5. FULL RESULTS/,$p' "$(report)" | grep -E '^\[[A-Z/]+\] [0-9]' |
        sed -E 's/^\[([A-Z/]+)\] ([0-9.]+) .*/\2\t\1/' | LC_ALL=C sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -k5,5n
}
