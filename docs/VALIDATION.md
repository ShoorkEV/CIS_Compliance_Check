# Validation status (milestone M5)

**Status: not done.** cis-audit 1.0.0 has been written and tested against *synthetic* fixtures
only. It has not been run on an Ubuntu 26.04 machine, so none of the following has been
established yet. Do not publish a "validated" claim until every box below is ticked.

## What exists

| Item | State |
| --- | --- |
| Catalog of all 350 recommendations, 274 Level 1 - Server rows with check type and parameters | done (`tools/coverage.sh` reports 350 / 274 / 0 todo) |
| 15 generic check types, 58 custom checks, 14 manual rows | implemented |
| Unit tests per check type (PASS, FAIL and N/A or ERROR case) and per custom check | `tests/unit/*.bats`, run against synthetic fixtures |
| Golden results for the `hardened`, `fresh` and `variant` fixtures | `tests/expected/*.tsv` (reviewed by hand against the Audit text; the fixtures are not real captures) |
| Static check for forbidden commands in runtime code | `tests/forbidden_commands.sh` (passes) |
| `shellcheck -x` | **not run** (no shellcheck on the development machine); runs in CI |
| bats | run through the bundled `tests/runbats.sh` subset runner; real bats runs in CI |

## What has to be done on test VMs

1. Build `fresh`, `hardened` and `variant` as described in the plan (section 12) and snapshot them.
2. On each VM run `tools/record_facts.sh tests/fixtures/<name>` and replace the synthetic
   fixtures; review the recordings for secrets before committing.
3. Re-run `bats tests/unit`. Differences between the synthetic and the recorded fixtures are
   expected (command output formats of uutils coreutils, sudo-rs, OpenSSH 10) and must be fixed in
   the collectors in `lib/facts.sh`.
4. Check every format string that depends on uutils on the real system, in particular
   `stat -Lc '%a %U %G %F'` (the script uses `%a`, never `%#a`), `find -print0`, `sort`, `date`, `ps -eo user:32=,args=`.
5. Run the script on each VM as root: `cis-audit.sh --verbose`. Compare the result per control
   with `tests/expected/<vm>.tsv` set by hand from the PDF Audit sections. Resolve every difference
   or record it in `tools/deviations.tsv` (-> `docs/CONTROLS.md`).
6. PDF snippet runner: for the controls whose PDF Audit is a self-contained script, run the repaired
   snippet and compare its PASS/FAIL with the script's state. Only `tools/reference/cis_6.1.3.1_audit.sh`
   and `tools/reference/cis_7.1.11_audit.sh` exist so far.
7. Mutation tests on a snapshot of `hardened`: `CIS_MUTATE_ON_TEST_VM=yes tests/mutations/mutate.sh dist/cis-audit.sh`
   (about 40 mutations are written; the plan asks for about 60, at least one per generic check type
   and per custom group). The list has not been run yet.
8. Read-only proof: `tests/readonly_proof.sh dist/cis-audit.sh` (checksums before and after, optional auditd watch on /etc).
9. Runtime with `--no-slow` must stay below two minutes on the VMs.
10. Run `dist/cis-audit.sh` alone on a clean VM and publish its checksum with the release.

## Things most likely to need a fix on a real system

* The output format of `systemctl list-unit-files` / `list-units --plain` for template, alias and
  generated units.
* `sshd -T` key names and value formatting (the script lower-cases nothing; it expects the
  lower-case key names OpenSSH prints).
* `systemd-sysctl --cat-config` header lines (`# /path/file.conf`) and `systemd-analyze cat-config`
  section handling.
* `findmnt -knP` quoting of option strings.
* The set of pseudo filesystems skipped by the filesystem walks (7.1.11, 7.1.12, 7.1.13).
* Whether `/etc/update-motd.d/*` at mode 0755 should fail 1.6.6 (the PDF's literal text says so).
