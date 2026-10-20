#!/usr/bin/env bats
# Golden results: the expected state of every Level 1 - Server control on each fixture
# (tests/expected/<fixture>.tsv). The files were reviewed control by control against the
# benchmark's Audit text and the fixture; they guard against unintended changes.
# The fixtures are synthetic, so these are regression tests, not a validation on real machines.

load helpers

golden() { # golden <fixture> [extra audit args]
    local name=$1
    shift
    fx "$name"
    audit "$@"
    [ "$status" -le 2 ]
    results_table >"$BATS_TEST_TMPDIR/actual.tsv"
    if ! diff -u "$ROOT_DIR/tests/expected/$name.tsv" "$BATS_TEST_TMPDIR/actual.tsv"; then
        return 1
    fi
}

@test "golden: hardened (nginx accepted through an exception)" {
    fx hardened
    printf '2.1.19 | nginx web server on 80/443 | V. Hoeck | 2999-12-31\n' >"$FX/exc.conf"
    audit --exceptions "$FX/exc.conf"
    results_table >"$BATS_TEST_TMPDIR/actual.tsv"
    diff -u "$ROOT_DIR/tests/expected/hardened.tsv" "$BATS_TEST_TMPDIR/actual.tsv"
    [ "$status" -eq 0 ]
}

@test "golden: fresh default install" {
    golden fresh
}

@test "golden: variant (rsyslog and systemd-timesyncd)" {
    golden variant
}

@test "golden: every Level 1 - Server control appears exactly once" {
    fx hardened
    audit
    results_table >"$BATS_TEST_TMPDIR/actual.tsv"
    [ "$(wc -l <"$BATS_TEST_TMPDIR/actual.tsv")" -eq 274 ]
    [ "$(cut -f1 "$BATS_TEST_TMPDIR/actual.tsv" | sort -u | wc -l)" -eq 274 ]
}
