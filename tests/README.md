# Tests

| What | Where | Needs |
| --- | --- | --- |
| Unit tests for the engine, every generic check type and the custom checks | `unit/engine.bats`, `unit/generic.bats`, `unit/custom.bats` | bats (or `runbats.sh`) |
| Golden results per control for three fixtures | `unit/golden.bats`, `expected/*.tsv` | bats |
| No system-changing command in runtime code | `forbidden_commands.sh` (`--selftest` proves it detects) | bash, grep -P |
| Mutation tests (one broken control at a time) | `mutations/mutate.sh` | **a test VM snapshot**, root |
| Read-only proof (checksums before/after, optional auditd watch) | `readonly_proof.sh` | **a test VM**, root |

```bash
bats tests/unit                         # all bats tests
bash tests/runbats.sh tests/unit/*.bats # same without bats installed (supports the subset the tests use)
bash tests/runbats.sh -f sysctl tests/unit/generic.bats   # only tests whose name contains "sysctl"
bash tests/make_fixtures.sh             # regenerate tests/fixtures (SYNTHETIC) -- review the diff
```

## How the offline tests work

The audit collects system state once into a *facts* directory (command output, one file per
fact) and reads configuration files through a root prefix. In test mode both come from a fixture:

```
CIS_AUDIT_TESTMODE=1                    skips the root check (the OS check still reads the fixture's os-release)
CIS_AUDIT_FACTS_DIR=<fixture>/facts     recorded command output; a missing fact file = fact unavailable (ERROR)
CIS_AUDIT_ROOTFS=<fixture>/rootfs       prefix for every file the checks read
<fixture>/facts/stat.tsv                path <TAB> mode <TAB> user <TAB> group <TAB> type (f|d); mode "-" = absent
```

These variables are ignored unless `CIS_AUDIT_TESTMODE` is set, so a root shell with stray
variables cannot redirect a real audit.

Each unit test copies a fixture, breaks exactly one thing, runs `cis-audit.sh --only <id>` and
asserts the state of that control.

## The fixtures are synthetic

`fixtures/hardened`, `fixtures/fresh` and `fixtures/variant` were written by `make_fixtures.sh`,
`make_fixtures_fresh.sh` and `make_fixtures_variant.sh` to look like a hardened server, a default
minimal install and a hardened server with rsyslog and systemd-timesyncd. **They are not captures
of a real Ubuntu 26.04 machine.** Replace them with `tools/record_facts.sh` recordings from the
test VMs (see `docs/VALIDATION.md`). The golden files in `expected/` were reviewed control by
control against the benchmark's Audit text and the synthetic fixtures; after re-recording they
must be re-reviewed by hand, not regenerated blindly (`gen_golden_candidates.sh` only produces
candidates).
