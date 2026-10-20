# cis-audit

A standalone, **read-only** bash script that audits one Ubuntu 26.04 LTS server against the
**CIS Ubuntu Linux 26.04 LTS Benchmark v1.0.0**, profile **Level 1 - Server** (274 recommendations),
and writes a text and an HTML compliance report.

* Never changes the system; writes only the report directory and a temp dir.
* One file to deploy: `dist/cis-audit.sh` (libraries and the control catalog are embedded).
* No Python, Perl, jq, network access or CIS-CAT/Tenable needed at runtime.
* Exceptions and site thresholds live in separate files that are parsed as data.
* Internal compliance check, not an official CIS-CAT result. CIS benchmark content is licensed for
  internal use only; keep the catalog and reports inside your organisation.

See `docs/USAGE.md` for options, exit codes and how to read the report, and `docs/CONTROLS.md` for
every control and every deviation from the PDF's audit text.

## Status

Version 1.0.0 is code-complete for milestones M0 to M4 and M6 of the development plan. **It has not
yet been run on a real Ubuntu 26.04 machine**: the test fixtures in `tests/fixtures/` are synthetic
(written by hand to look like a hardened and a default install), and milestone M5 (validation on the
`fresh`, `hardened` and `variant` VMs, mutation tests, read-only proof, PDF snippet runner) still has
to be done. Treat results as unvalidated until M5 is signed off.

## Layout

```
cis-audit.sh            entry point: CLI, preflight, orchestration
lib/                    core, facts (all commands live here), applicability, checks, reports
lib/checks_custom/      cus_<id> functions, one file per benchmark section
catalog/controls.tsv    all 350 recommendations; v1 implements the 274 Level 1 - Server rows
etc/                    site.conf.example, exceptions.conf.example
tools/                  development only: catalog extraction, coverage, fixture recorder, bundler
tests/                  bats tests, synthetic fixtures, golden results
docs/                   USAGE.md, CONTROLS.md (generated)
dist/cis-audit.sh       the single-file build (tools/build_single.sh)
```

## Development

```bash
python3 tools/parse.py bench.txt recs.json        # after: pdftotext -enc UTF-8 -layout <benchmark.pdf> bench.txt
python3 tools/extract_catalog.py recs.json catalog/controls.tsv
bash tools/coverage.sh recs.json                  # 350 rows / 274 Level 1 - Server / 0 todo / every function present
bash tests/make_fixtures.sh                       # regenerate the synthetic fixtures
bats tests/unit                                   # or: bash tests/runbats.sh tests/unit/*.bats
bash tests/forbidden_commands.sh                  # no system-changing command in runtime code
shellcheck -x cis-audit.sh lib/*.sh lib/checks_custom/*.sh
bash tools/build_single.sh                        # dist/cis-audit.sh + .sha256
python3 tools/gen_controls_md.py > docs/CONTROLS.md
```

Audit logic and thresholds come only from the benchmark PDF. No logic or text from the Tenable
`.audit` file is used.

## CI

`docs/ci-workflow.yml` is the GitHub Actions workflow (shellcheck, bats, coverage, forbidden-command scan, build check). It is shipped under docs/ because the token used for the first push had no `workflow` scope; copy it to `.github/workflows/ci.yml` to enable it.
