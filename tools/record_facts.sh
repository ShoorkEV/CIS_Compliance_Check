#!/usr/bin/env bash
# tools/record_facts.sh - capture a test fixture from a TEST VM (development only).
#
# usage (as root, on a test VM, never on production):
#   tools/record_facts.sh tests/fixtures/<name>
#
# Writes <name>/facts/*  (every fact the audit collects, plus stat.tsv) and
# <name>/rootfs/*        (the configuration files the checks read; password hashes in
#                         /etc/shadow are replaced by a placeholder).
# Then run the audit against it offline:
#   tests/run_fixture.sh <name> --verbose
set -u
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEST=${1:?usage: record_facts.sh <fixture dir>}
(( EUID == 0 )) || { echo "run as root on a test VM" >&2; exit 3; }
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

# shellcheck source=../lib/core.sh
source "$HERE/../lib/core.sh"
# shellcheck source=../lib/facts.sh
source "$HERE/../lib/facts.sh"

FACTS_DIR=$DEST/facts
mkdir -p "$FACTS_DIR" "$DEST/rootfs"
FIXTURE_MODE=0

for f in dpkg unit_files units_all mounts sysctl_running sysctl_cat sshd_T modprobe_cfg lsmod \
    kmod_files ss_listen ufw_status apt_config apt_policy aa_status ps_chronyd root_path mta_cfg \
    apt_keyfiles logfiles wireless_modules home_dots fs_world fs_nouser fs_suid sudo_log; do
    fact "$f" || echo "note: fact $f could not be collected: ${FACT_ERR[$f]-}" >&2
done
if grep -Pqs '^\s*Match\s+(User|Group|Host|LocalAddress|LocalPort|Address)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; then
    fact sshd_T_C || true
fi
for c in systemd/journald.conf systemd/coredump.conf systemd/timesyncd.conf; do fact catcfg "$c" || true; done

# configuration files and directories the checks read
mapfile -t paths < <(grep -v '^\s*#' "$HERE/record_files.list" | grep -v '^\s*$')
: >"$FACTS_DIR/stat.tsv"
for p in "${paths[@]}"; do
    for m in $p; do
        [[ -e $m ]] || continue
        read -r mode user grp kind < <(stat -Lc '%a %U %G %F' -- "$m")
        t=f; [[ $kind == *directory* ]] && t=d
        printf '%s\t%s\t%s\t%s\t%s\n' "$m" "$mode" "$user" "$grp" "$t" >>"$FACTS_DIR/stat.tsv"
        if [[ $t == f ]]; then
            mkdir -p "$DEST/rootfs$(dirname -- "$m")"
            if [[ $m == /etc/shadow || $m == /etc/shadow- ]]; then
                sed -E 's/^([^:]*):(\$[^:]*):/\1:$redacted$hash:/' "$m" >"$DEST/rootfs$m"
            else
                cp -L -- "$m" "$DEST/rootfs$m"
            fi
        else
            mkdir -p "$DEST/rootfs$m"
        fi
    done
done
echo "recorded $DEST (review it for secrets before committing)"
