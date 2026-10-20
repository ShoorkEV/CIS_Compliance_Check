# cis-audit usage

`cis-audit.sh` audits one Ubuntu 26.04 LTS server against the **CIS Ubuntu Linux 26.04 LTS
Benchmark v1.0.0**, profile **Level 1 - Server** (274 recommendations), and writes a text and an
HTML report. It is read-only and its result is an internal compliance check, not an official
CIS-CAT result.

## Requirements

| Item | Requirement |
| --- | --- |
| OS | Ubuntu 26.04 LTS (`ID=ubuntu`, `VERSION_ID="26.04"`); anything else exits with code 3 unless `--force-os` is given |
| User | root (needed for `/etc/shadow`, `/etc/gshadow` and `sshd -T`), otherwise exit code 3 |
| Shell | bash 5.2 or newer |
| Tools | only what a minimal Ubuntu 26.04 Server has: coreutils (uutils), findutils, grep with `-P`, sed, mawk, util-linux (`findmnt`), procps, iproute2, kmod, systemd tools, dpkg/apt, openssh-server. No Python, Perl, jq, gawk or network access |

The script never changes the system. It writes only the report directory and a private
temporary directory that is removed on exit.

## Install and run

`dist/cis-audit.sh` is one self-contained file (libraries and the control catalog are embedded).

```bash
sudo install -m 0755 cis-audit.sh /usr/local/sbin/cis-audit.sh      # optional
sha256sum -c cis-audit.sh.sha256                                    # verify the download
sudo ./cis-audit.sh --output /var/tmp/cis-reports
```

Optional site files (both are parsed as data, never executed):

```bash
sudo mkdir -p /etc/cis-audit
sudo cp site.conf.example /etc/cis-audit/site.conf
sudo cp exceptions.conf.example /etc/cis-audit/exceptions.conf
```

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--level N` | `1` | Cumulative level. `2` also lists the Level 2 rows, reported as SKIPPED / NOT IMPLEMENTED |
| `--profile server` | `server` | Only `server` in v1; `workstation` exits with code 3 |
| `--section LIST` | all | Comma list of ID prefixes to run (`1,5.3`) |
| `--only LIST` | all | Run only these IDs or prefixes (`5.1.7,6.3.2`) |
| `--skip LIST` | none | Report these as SKIPPED; wins over `--only` |
| `--config FILE` | `/etc/cis-audit/site.conf` if present | Site values (see below) |
| `--exceptions FILE` | `/etc/cis-audit/exceptions.conf` if present | Accepted deviations |
| `--output DIR` | `./cis-audit-reports` | Report directory, created with mode 0700 |
| `--format LIST` | `text,html` | Which reports to write |
| `--no-slow` | off | Skip the filesystem walks (7.1.11, 7.1.12, 7.1.13, 6.1.3.1) |
| `--timeout SECONDS` | `60` | Time limit per external command (five times as much for the filesystem walks) |
| `--verbose` | off | Print the evidence for every control on screen |
| `--quiet`, `--no-color` | off | Less output / no colour |
| `--force-os` | off | Continue on a different OS release |
| `--list` | | Print the filtered catalog (ID, level, check type, title) and exit 0 without auditing |
| `--version`, `--help` | | |

Examples:

```bash
sudo ./cis-audit.sh --no-slow                              # quick run, about a minute or less
sudo ./cis-audit.sh --section 5 --verbose                  # only access and authentication, evidence on screen
sudo ./cis-audit.sh --only 5.1.7,5.1.17 --format text
./cis-audit.sh --list --section 2.1                        # no root needed to list
```

## Result states and exit codes

| State | Meaning | Counts in the score |
| --- | --- | --- |
| PASS | Compliant | yes |
| FAIL | Not compliant | yes |
| EXCEPTION | A FAIL covered by a valid exception | no, listed separately |
| MANUAL | Needs a human decision; the evidence that could be collected is attached | no |
| N/A | The `applies_if` condition is false (for example no gdm3, no cron, journald instead of rsyslog); the reason is given | no |
| SKIPPED | Excluded by `--no-slow`, `--skip`, or not implemented (Level 2) | no |
| ERROR | The check could not run (timeout, missing tool, parse error) | no, but it blocks a clean exit |

Score = PASS / (PASS + FAIL), overall and per section.

| Exit code | When |
| --- | --- |
| 0 | No FAIL and no ERROR |
| 1 | At least one FAIL |
| 2 | No FAIL, but at least one ERROR (the audit is incomplete) |
| 3 | Usage or precondition error: not root, wrong OS, invalid options, invalid `site.conf` or exceptions file |

## Reading the report

`cis-audit_<hostname>_<YYYYmmdd-HHMMSS>.txt` and `.html` (mode 0600; they contain user names and
configuration details) hold the same content in the same order:

1. **Header** - host, FQDN, OS, kernel, run times, benchmark and profile, script version, SHA-256 of the catalog, `site.conf` and `exceptions.conf` used, the options given.
2. **Summary** - counts per state, the overall score, a table per benchmark section 1 to 7.
3. **Findings** - every FAIL and ERROR with its evidence, then every MANUAL control with the evidence collected and the decision it needs.
4. **Exceptions** - ID, justification, approver, expiry date, days left; expired ones are flagged.
5. **Full results** - every control in ID order with state, title and evidence.

Every FAIL says what was found, where (file and line, or the command whose output was used) and
what was expected. The first evidence line of a FAIL is the finding. The text report is plain ASCII
within 100 columns. The HTML report is a single file (inline CSS and JavaScript, no external
resources) with state filter buttons, a search box for ID and title, collapsible evidence and a
print stylesheet; every value taken from the host is HTML-escaped.

## site.conf

`KEY=value` lines; `#` starts a comment. Unknown keys, bad syntax, or a value **weaker** than the
benchmark stop the run with exit code 3 (use the exceptions file for an accepted weaker setting).
Defaults are the benchmark values; `etc/site.conf.example` names the control each one comes from.
Besides thresholds, `TIME_DAEMON` (`auto|chrony|timesyncd`) and `LOGGER` (`auto|journald|rsyslog`)
override the automatic detection that decides which of the 2.3.x and 6.1.x controls apply, and
`BANNER_FILE` is compared byte for byte with `/etc/issue` and `/etc/issue.net`.

## exceptions.conf

```
# id | justification | approved_by | expires (YYYY-MM-DD)
2.1.19 | Host is the production web server (nginx on 80/443) | V. Hoeck | 2027-10-31
```

| Situation | Reported state |
| --- | --- |
| Check FAILs, valid exception exists | EXCEPTION (justification, approver, expiry shown) |
| Check FAILs, exception expired | FAIL with the note "exception expired on <date>" |
| Check PASSes, exception exists | PASS with the note "exception no longer needed" |
| Exception for an ID that is not in the catalog | the run stops with exit code 3 |

Exceptions apply only to FAIL. They never turn ERROR or MANUAL into a pass.

## Known limits

* Run locally (or push the file over ssh); there is no remote scanning.
* Controls that need a network (for example `apt update` in 1.2.2.1) are MANUAL; "latest version"
  checks (5.3.1.x) use the local `apt-cache policy` data.
* GDM (1.7.x) is N/A without `gdm3` and MANUAL when it is installed.
* Level 2 - Server and the Workstation profiles are not audited in v1.
* `docs/CONTROLS.md` lists every control, its check type, its applicability, and every place where
  this script differs from the literal audit text of the PDF.
* The CIS benchmark text is licensed for internal use. Keep the catalog and reports inside your
  organisation.
