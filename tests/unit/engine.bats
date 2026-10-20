#!/usr/bin/env bats
# CLI, preflight, selection, exit codes, site.conf, exceptions, reports.

load helpers

@test "--version prints the version" {
    run bash "$AUDIT" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"cis-audit 1.0.0"* ]]
}

@test "--help lists the documented options" {
    run bash "$AUDIT" --help
    [ "$status" -eq 0 ]
    for o in --level --profile --section --only --skip --config --exceptions --output --format --no-slow --timeout --verbose --quiet --no-color --force-os --list --version; do
        [[ "$output" == *"$o"* ]]
    done
}

@test "--list prints the 274 Level 1 Server rows and exits 0" {
    run bash "$AUDIT" --list
    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 274 ]
    [[ "${lines[0]}" == $'1.1.1.1\t1\tkmod_unavailable\t'* ]]
}

@test "--list --level 2 prints all 350 rows" {
    run bash "$AUDIT" --list --level 2
    [ "$status" -eq 0 ]
    [ "${#lines[@]}" -eq 350 ]
}

@test "--section and --only select by id prefix" {
    run bash "$AUDIT" --list --section 5.3.2
    [ "${#lines[@]}" -eq 4 ]
    run bash "$AUDIT" --list --only 5.1.7,6.3.2
    [ "${#lines[@]}" -eq 2 ]
}

@test "an unknown option or id prefix exits 3" {
    run bash "$AUDIT" --frobnicate
    [ "$status" -eq 3 ]
    run bash "$AUDIT" --list --only 99.9
    [ "$status" -eq 3 ]
}

@test "--profile workstation exits 3" {
    run bash "$AUDIT" --profile workstation --list
    [ "$status" -eq 3 ]
}

@test "not running as root exits 3" {
    [ "$(id -u)" -ne 0 ] || skip "running as root"
    run bash "$AUDIT" --only 1.1.1.1
    [ "$status" -eq 3 ]
    [[ "$output" == *"root"* ]]
}

@test "an OS other than Ubuntu 26.04 exits 3 unless --force-os is given" {
    fx hardened
    sed -i 's/^VERSION_ID=.*/VERSION_ID="24.04"/' "$RFS/etc/os-release"
    check 1.1.1.1
    [ "$status" -eq 3 ]
    [[ "$output" == *"26.04"* ]]
    check 1.1.1.1 --force-os
    [ "$status" -eq 0 ]
}

@test "a clean control gives exit 0, a failing control exit 1" {
    fx hardened
    check 7.1.1
    [ "$status" -eq 0 ]
    sset /etc/passwd 666 root root
    check 7.1.1
    [ "$status" -eq 1 ]
}

@test "a missing fact gives ERROR and exit 2 when nothing fails" {
    fx hardened
    rm "$FACTS/sysctl_running"
    check 3.3.1.1
    [ "$status" -eq 2 ]
    assert_state 3.3.1.1 ERROR
}

@test "--no-slow reports the filesystem walks as SKIPPED" {
    fx hardened
    audit --section 7.1 --no-slow
    assert_state 7.1.11 SKIPPED
    assert_state 7.1.12 SKIPPED
    assert_state 7.1.13 SKIPPED
    assert_state 7.1.1 PASS
}

@test "--skip wins over --only and shows SKIPPED" {
    fx hardened
    audit --only 7.1.1,7.1.2 --skip 7.1.2
    assert_state 7.1.1 PASS
    assert_state 7.1.2 SKIPPED
}

@test "--level 2 reports Level 2 rows as NOT IMPLEMENTED" {
    fx hardened
    audit --only 6.2.1.1 --level 2
    assert_state 6.2.1.1 SKIPPED
    [[ "$(evidence_of 6.2.1.1)" == *"NOT IMPLEMENTED"* ]]
}

@test "reports are written as text and html next to each other" {
    fx hardened
    audit --only 7.1.1 --format text,html
    [ "$status" -eq 0 ]
    [ -n "$(ls "$OUT"/*.txt)" ]
    [ -n "$(ls "$OUT"/*.html)" ]
}

@test "report files are mode 0600 and the directory 0700" {
    [[ "$OSTYPE" == linux* ]] || skip "needs POSIX permissions"
    fx hardened
    check 7.1.1
    [ "$(stat -c %a "$OUT")" = "700" ]
    [ "$(stat -c %a "$(report)")" = "600" ]
}

@test "the text report has the five sections in order and stays within 100 columns" {
    fx fresh
    audit --section 7.2
    f=$(report)
    n1=$(grep -n '^1. SUMMARY' "$f" | cut -d: -f1)
    n2=$(grep -n '^2. FINDINGS' "$f" | cut -d: -f1)
    n3=$(grep -n '^3. MANUAL' "$f" | cut -d: -f1)
    n4=$(grep -n '^4. EXCEPTIONS' "$f" | cut -d: -f1)
    n5=$(grep -n '^5. FULL RESULTS' "$f" | cut -d: -f1)
    [ "$n1" -lt "$n2" ] && [ "$n2" -lt "$n3" ] && [ "$n3" -lt "$n4" ] && [ "$n4" -lt "$n5" ]
    ! awk 'length($0) > 100 { exit 1 }' "$f"
    ! grep -q $'\e' "$f"
}

@test "HTML report escapes values taken from the system" {
    fx fresh
    printf '666\troot\troot\t/var/log/<script>alert(1)</script>\x27"&.log\n' >"$FACTS/logfiles"
    audit --only 6.1.3.1 --format html
    html=$(ls "$OUT"/*.html)
    ! grep -q '<script>alert' "$html"
    grep -q '&lt;script&gt;alert(1)&lt;/script&gt;' "$html"
    grep -q '&#39;&quot;&amp;.log' "$html"
}

@test "HTML report is one self-contained file" {
    fx hardened
    audit --only 7.1.1 --format html
    html=$(ls "$OUT"/*.html)
    ! grep -Eqi '(src|href)="?https?://' "$html"
    ! grep -Eqi '<link ' "$html"
    ! grep -Eqi '@import|<img ' "$html"
}

# ---- site.conf --------------------------------------------------------------
@test "site.conf: a stricter value is used" {
    fx hardened
    printf 'SSH_MAX_AUTH_TRIES=3\n' >"$FX/site.conf"
    sed -i 's/^maxauthtries .*/maxauthtries 4/' "$FACTS/sshd_T"
    check 5.1.18 --config "$FX/site.conf"
    assert_state 5.1.18 FAIL
}

@test "site.conf: a value weaker than the benchmark exits 3" {
    fx hardened
    printf 'SSH_MAX_AUTH_TRIES=6\n' >"$FX/site.conf"
    check 5.1.18 --config "$FX/site.conf"
    [ "$status" -eq 3 ]
    [[ "$output" == *"weaker than the benchmark"* ]]
}

@test "site.conf: unknown key and bad syntax exit 3" {
    fx hardened
    printf 'NOT_A_KEY=1\n' >"$FX/site.conf"
    check 5.1.18 --config "$FX/site.conf"
    [ "$status" -eq 3 ]
    printf 'this is not a setting\n' >"$FX/site.conf"
    check 5.1.18 --config "$FX/site.conf"
    [ "$status" -eq 3 ]
}

@test "site.conf is parsed as data, never executed" {
    fx hardened
    printf 'BANNER_FILE=/x\n$(touch %s/pwned)\n' "$BATS_TEST_TMPDIR" >"$FX/site.conf"
    check 5.1.18 --config "$FX/site.conf"
    [ "$status" -eq 3 ]
    [ ! -e "$BATS_TEST_TMPDIR/pwned" ]
}

# ---- exceptions -------------------------------------------------------------
@test "exception: a FAIL with a valid exception becomes EXCEPTION" {
    fx hardened
    printf '2.1.19 | nginx web server | V. Hoeck | 2999-12-31\n' >"$FX/exc.conf"
    check 2.1.19 --exceptions "$FX/exc.conf"
    assert_state 2.1.19 EXCEPTION
    [ "$status" -eq 0 ]
    [[ "$(cat "$(report)")" == *"V. Hoeck"* ]]
}

@test "exception: an expired exception leaves the FAIL with a note" {
    fx hardened
    printf '2.1.19 | nginx web server | V. Hoeck | 2020-01-31\n' >"$FX/exc.conf"
    check 2.1.19 --exceptions "$FX/exc.conf"
    assert_state 2.1.19 FAIL
    [ "$status" -eq 1 ]
    [[ "$(cat "$(report)")" == *"exception expired on 2020-01-31"* ]]
}

@test "exception: a passing control keeps PASS and notes the exception is no longer needed" {
    fx hardened
    printf '7.1.1 | historic | V. Hoeck | 2999-12-31\n' >"$FX/exc.conf"
    check 7.1.1 --exceptions "$FX/exc.conf"
    assert_state 7.1.1 PASS
    [[ "$(cat "$(report)")" == *"exception no longer needed"* ]]
}

@test "exception: ERROR and MANUAL are never turned into an exception" {
    fx hardened
    printf '2.1.23 | accepted | V. Hoeck | 2999-12-31\n3.3.1.1 | accepted | V. Hoeck | 2999-12-31\n' >"$FX/exc.conf"
    rm "$FACTS/sysctl_running"
    audit --only 2.1.23,3.3.1.1 --exceptions "$FX/exc.conf"
    assert_state 2.1.23 MANUAL
    assert_state 3.3.1.1 ERROR
}

@test "exception: an unknown control id exits 3" {
    fx hardened
    printf '9.9.9 | typo | V. Hoeck | 2999-12-31\n' >"$FX/exc.conf"
    check 2.1.19 --exceptions "$FX/exc.conf"
    [ "$status" -eq 3 ]
}

@test "exception: a bad date or wrong field count exits 3" {
    fx hardened
    printf '2.1.19 | nginx | V. Hoeck | 2999-13-40\n' >"$FX/exc.conf"
    check 2.1.19 --exceptions "$FX/exc.conf"
    [ "$status" -eq 3 ]
    printf '2.1.19 | nginx | V. Hoeck\n' >"$FX/exc.conf"
    check 2.1.19 --exceptions "$FX/exc.conf"
    [ "$status" -eq 3 ]
}

# ---- read-only guarantee ------------------------------------------------------
@test "runtime code never contains a forbidden system-changing command" {
    run bash "$ROOT_DIR/tests/forbidden_commands.sh"
    [ "$status" -eq 0 ]
}

@test "the audit does not modify the fixture it reads" {
    fx hardened
    before=$(cd "$FX" && find . -type f -exec cksum {} + | sort)
    audit --section 5
    after=$(cd "$FX" && find . -type f -exec cksum {} + | sort)
    [ "$before" = "$after" ]
}

# ---- shipped files --------------------------------------------------------------
@test "the shipped example config and exceptions files are valid" {
    fx hardened
    check 5.1.18 --config "$ROOT_DIR/etc/site.conf.example" --exceptions "$ROOT_DIR/etc/exceptions.conf.example"
    [ "$status" -eq 0 ]
    assert_state 5.1.18 PASS
}

@test "the single-file build runs on its own and gives the same results" {
    fx hardened
    bash "$ROOT_DIR/tools/build_single.sh" "$BATS_TEST_TMPDIR/single/cis-audit.sh"
    run bash "$BATS_TEST_TMPDIR/single/cis-audit.sh" --list
    [ "${#lines[@]}" -eq 274 ]
    CIS_AUDIT_TESTMODE=1 CIS_AUDIT_FACTS_DIR="$FACTS" CIS_AUDIT_ROOTFS="$RFS" \
        run bash "$BATS_TEST_TMPDIR/single/cis-audit.sh" --only 5.1.22,7.1.5,2.1.19 --output "$OUT" --format text --no-color --quiet
    [ "$status" -eq 1 ]
    assert_state 5.1.22 PASS
    assert_state 7.1.5 PASS
    assert_state 2.1.19 FAIL
}
