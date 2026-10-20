# Open questions for the owner

The plan (section 13) says to ask before deviating from the PDF logic, changing the CLI, adding a
runtime dependency, or marking an Automated control MANUAL. The build ran without a reviewer, so
these decisions were taken with the safest reading and are listed here for review. Each has a row
in `docs/CONTROLS.md` (source: `tools/deviations.tsv`).

| # | Control | What was decided | Alternative |
| --- | --- | --- | --- |
| 1 | 1.6.6 | The PDF's literal text (`/etc/update-motd.d/*` at mode 0644 or stricter) is applied, so a default Ubuntu install FAILS. | Exclude `/etc/update-motd.d/*` (executable scripts); or accept the FAIL through exceptions.conf. |
| 2 | 2.1.22 | The PDF script's interface test (accepts 0.0.0.0, rejects 127.0.0.1) looks inverted; loopback values are accepted and `postconf inet_interfaces` (effective value) replaces `postconf -n`. | Port the script literally. |
| 3 | 5.2.3 | The audit never runs sudo, so it cannot "generate a recent event". Existing sudo / sudo-rs entries in the journal or `/var/log/auth.log` count; a host without any FAILS with a hint. | Report MANUAL when there is no evidence (needs approval: the PDF calls the control Automated). |
| 4 | 1.2.1.10, 1.2.1.11 | Stricter than the PDF regular expression: also `deb-src`, an options bracket before the URI, and every token on a deb822 `URIs:` line (the plan asks for this parsing). | Literal PDF regex. |
| 5 | 1.2.1.12 - 1.2.1.15 | A setting absent from `apt-config dump` is a FAIL ("verify the output includes"). | Treat absent as the compiled-in default. |
| 6 | 1.7.1 - 1.7.6 | N/A without gdm3; MANUAL with a hint when gdm3 is installed (as the plan says for v1). | Automate the gsettings checks. |
| 7 | 6.3.2 | PDF only: `dailyaidecheck.timer`. The plan also mentions an AIDE cron job; it is not accepted. | Accept a cron job. |
| 8 | 5.4.2.5 | Root's PATH comes from `env -i ... bash -l -c 'printenv PATH'` instead of `sudo su - root -c env` to avoid a PAM session and auth.log noise. A login shell does run /etc/profile and /root/.profile. | Run the PDF command, or parse the files statically. |
| 9 | 2.4.1.2 - 2.4.1.8, 5.1.2 | "No access for group or other" is applied as a maximum mode of 0700. | 0600 for files. |
| 10 | 7.1.2, 7.1.4, 7.1.6, 7.1.8, 1.2.1.5, 1.2.1.6, 2.4.1.7 | A missing optional file or directory passes. | FAIL when missing. |
| 11 | test hooks | `CIS_AUDIT_TESTMODE`, `CIS_AUDIT_FACTS_DIR`, `CIS_AUDIT_ROOTFS`, `CIS_AUDIT_CATALOG` exist for the offline tests. They are ignored unless `CIS_AUDIT_TESTMODE` is set. They are not part of the documented CLI. | Remove them from the shipped single file. |
| 12 | publishing | The catalog, the reference scripts and `docs/CONTROLS.md` contain CIS benchmark text. The plan limits them to the organisation. They must not be pushed to a public repository. | - |
