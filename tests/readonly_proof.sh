#!/usr/bin/env bash
# tests/readonly_proof.sh - read-only proof for a TEST VM (plan section 12, M5).
#
# Records checksums and state of the places an audit must not touch, runs a full audit,
# records them again and fails on any difference. With CIS_PROOF_AUDITD=yes it also puts an
# auditd watch on /etc for the duration of the run and fails on write events by the script.
#
#   sudo tests/readonly_proof.sh /path/to/cis-audit.sh
#
# STATUS: written but not yet run on a VM.
set -u
(( EUID == 0 )) || { echo "run as root" >&2; exit 3; }
AUDIT=${1:?usage: readonly_proof.sh /path/to/cis-audit.sh}
WORK=$(mktemp -d /var/tmp/cis-proof.XXXXXX)
trap 'rm -rf -- "$WORK"' EXIT

snapshot() { # snapshot <name>
    local d=$WORK/$1
    mkdir -p "$d"
    find /etc -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum >"$d/etc.sha" 2>/dev/null
    find /etc -xdev \( -type d -o -type l \) -print0 2>/dev/null | sort -z | xargs -0 stat -c '%n %a %U %G %Y' >"$d/etc.dirs" 2>/dev/null
    find /boot/grub -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum >"$d/grub.sha" 2>/dev/null
    find /usr/lib/modules -xdev -printf '%p %m %u %g %T@\n' 2>/dev/null | sort >"$d/modules.meta"
    systemctl list-unit-files --no-pager 2>/dev/null >"$d/units"
    sysctl -a 2>/dev/null | sort >"$d/sysctl"
    lsmod | sort >"$d/lsmod"
    ufw status verbose 2>/dev/null >"$d/ufw"
    dpkg -l 2>/dev/null >"$d/dpkg"
    ls -l /var/lib/apt/lists 2>/dev/null | grep -v '^total' >"$d/apt-lists"
}

WATCH=0
if [[ ${CIS_PROOF_AUDITD-} == yes ]] && command -v auditctl >/dev/null 2>&1; then
    auditctl -w /etc -p wa -k cis_audit_proof >/dev/null 2>&1 && WATCH=1
fi
snapshot before
bash "$AUDIT" --quiet --format text --output "$WORK/reports" >/dev/null 2>&1
snapshot after
rc=0
for f in etc.sha etc.dirs grub.sha modules.meta units sysctl lsmod ufw dpkg apt-lists; do
    if ! diff -q "$WORK/before/$f" "$WORK/after/$f" >/dev/null; then
        echo "DIFFERENCE in $f:"
        diff "$WORK/before/$f" "$WORK/after/$f" | head -n 20
        rc=1
    fi
done
if (( WATCH )); then
    auditctl -W /etc -p wa -k cis_audit_proof >/dev/null 2>&1
    ev=$(ausearch -k cis_audit_proof -ts recent 2>/dev/null | grep -c 'comm="cis-audit' || true)
    if (( ev > 0 )); then echo "auditd saw $ev write events from the script under /etc"; rc=1; fi
fi
(( rc == 0 )) && echo "read-only proof passed: nothing changed"
exit "$rc"
