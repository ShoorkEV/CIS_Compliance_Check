#!/usr/bin/env bash
# tests/mutations/mutate.sh - mutation tests for a TEST VM SNAPSHOT (plan section 12).
#
# Breaks one control at a time on a hardened VM and checks that the audit reports exactly
# that control (and the listed related controls) as FAIL while every other control keeps
# its baseline state. NEVER run this on a production host: it changes the system.
#
#   sudo CIS_MUTATE_ON_TEST_VM=yes tests/mutations/mutate.sh /path/to/cis-audit.sh [--only ID] [--fast]
#
# --fast  run only the mutated control (--only) instead of the whole audit; checks that it FAILs
# --only  run a single mutation
#
# STATUS: written but not yet run on a VM (no Ubuntu 26.04 machine was available while the
# script was developed). Expect to adjust the mutations to how the hardened VM was built.
set -u
[[ ${CIS_MUTATE_ON_TEST_VM-} == yes ]] || { echo "refusing to run: set CIS_MUTATE_ON_TEST_VM=yes on a test VM snapshot" >&2; exit 3; }
(( EUID == 0 )) || { echo "run as root" >&2; exit 3; }
AUDIT=${1:?usage: mutate.sh /path/to/cis-audit.sh [--only ID] [--fast]}
shift
ONLY="" FAST=0
while (( $# )); do
    case $1 in
        --only) ONLY=$2; shift 2 ;;
        --fast) FAST=1; shift ;;
        *) echo "unknown option $1" >&2; exit 3 ;;
    esac
done
WORK=$(mktemp -d /var/tmp/cis-mutate.XXXXXX)
trap 'rm -rf -- "$WORK"' EXIT

# id[,related ids] | apply | revert
MUTATIONS=(
    '7.1.5|chmod 0644 /etc/shadow|chmod 0640 /etc/shadow'
    '7.1.1|chmod 0666 /etc/passwd|chmod 0644 /etc/passwd'
    '7.1.9|chown nobody /etc/shells|chown root /etc/shells'
    '7.1.11|touch /srv/cis-mut-ww && chmod 0666 /srv/cis-mut-ww|rm -f /srv/cis-mut-ww'
    '7.1.12|touch /srv/cis-mut-orphan && chown 61234:61234 /srv/cis-mut-orphan|rm -f /srv/cis-mut-orphan'
    '5.1.22|printf "PermitRootLogin yes\n" >/etc/ssh/sshd_config.d/00-cis-mut.conf; chmod 600 /etc/ssh/sshd_config.d/00-cis-mut.conf|rm -f /etc/ssh/sshd_config.d/00-cis-mut.conf'
    '5.1.18|printf "MaxAuthTries 6\n" >/etc/ssh/sshd_config.d/00-cis-mut.conf; chmod 600 /etc/ssh/sshd_config.d/00-cis-mut.conf|rm -f /etc/ssh/sshd_config.d/00-cis-mut.conf'
    '5.1.7|printf "Ciphers aes128-cbc,aes256-ctr\n" >/etc/ssh/sshd_config.d/00-cis-mut.conf; chmod 600 /etc/ssh/sshd_config.d/00-cis-mut.conf|rm -f /etc/ssh/sshd_config.d/00-cis-mut.conf'
    '5.1.1|chmod 0644 /etc/ssh/sshd_config|chmod 0600 /etc/ssh/sshd_config'
    '3.3.1.1|sysctl -w net.ipv4.ip_forward=1|sysctl -w net.ipv4.ip_forward=0'
    '3.3.1.12|sysctl -w net.ipv4.conf.all.rp_filter=0|sysctl -w net.ipv4.conf.all.rp_filter=1'
    '1.5.9|sysctl -w kernel.randomize_va_space=0|sysctl -w kernel.randomize_va_space=2'
    '3.3.1.1|printf "net.ipv4.ip_forward = 1\n" >/etc/sysctl.d/99-cis-mut.conf|rm -f /etc/sysctl.d/99-cis-mut.conf'
    '1.1.1.1|modprobe -n cramfs >/dev/null; M=$(modinfo -n cramfs 2>/dev/null); [ -n "$M" ] && insmod "$M"|rmmod cramfs 2>/dev/null; true'
    '1.1.2.2.4|mount -o remount,exec /dev/shm|mount -o remount,noexec /dev/shm'
    '1.5.10|cp -a /etc/security/limits.d /var/tmp/cis-mut-limits && rm -f /etc/security/limits.d/*cis*.conf|rm -rf /etc/security/limits.d && cp -a /var/tmp/cis-mut-limits /etc/security/limits.d && rm -rf /var/tmp/cis-mut-limits'
    '5.4.3.3|printf "umask 022\n" >/etc/profile.d/99-cis-mut.sh|rm -f /etc/profile.d/99-cis-mut.sh'
    '5.4.3.2|printf "TMOUT=7200\n" >/etc/profile.d/99-cis-mut.sh|rm -f /etc/profile.d/99-cis-mut.sh'
    '5.2.2|printf "Defaults !use_pty\n" >/etc/sudoers.d/99-cis-mut; chmod 440 /etc/sudoers.d/99-cis-mut|rm -f /etc/sudoers.d/99-cis-mut'
    '5.2.6|printf "Defaults timestamp_timeout=60\n" >/etc/sudoers.d/99-cis-mut; chmod 440 /etc/sudoers.d/99-cis-mut|rm -f /etc/sudoers.d/99-cis-mut'
    '5.2.5|printf "root ALL=(ALL) !authenticate ALL\n" >/etc/sudoers.d/99-cis-mut; chmod 440 /etc/sudoers.d/99-cis-mut|rm -f /etc/sudoers.d/99-cis-mut'
    '5.4.2.1,7.2.5|printf "cismut:x:0:0::/root:/bin/false\n" >>/etc/passwd|sed -i "/^cismut:/d" /etc/passwd'
    '7.2.7|printf "root:x:0:0:dup:/root:/bin/bash\n" >>/etc/passwd|sed -i "$ d" /etc/passwd'
    '7.2.4|usermod -aG shadow root|gpasswd -d root shadow'
    '5.4.2.8|useradd -r -s /usr/sbin/nologin cismut2 && usermod -p "$6$x$y" cismut2|userdel cismut2'
    '2.1.19|apt-get install -y apache2 >/dev/null 2>&1 && systemctl enable --now apache2|systemctl disable --now apache2; apt-get remove -y apache2 >/dev/null 2>&1'
    '2.2.4|apt-get install -y telnet >/dev/null 2>&1|apt-get remove -y telnet >/dev/null 2>&1'
    '1.5.6|apt-get install -y prelink >/dev/null 2>&1|apt-get remove -y prelink >/dev/null 2>&1'
    '4.1.2,4.1.3,4.1.5|ufw --force disable|ufw --force enable'
    '2.4.1.2|chmod 0644 /etc/crontab|chmod 0600 /etc/crontab'
    '2.4.1.8|chmod 0755 /etc/cron.d|chmod 0700 /etc/cron.d'
    '1.4.2|chmod 0644 /boot/grub/grub.cfg|chmod 0600 /boot/grub/grub.cfg'
    '1.6.2|printf "Ubuntu \\n\n" >/etc/issue.d/99-cis-mut|rm -f /etc/issue.d/99-cis-mut'
    '5.3.3.2.2|printf "minlen = 8\n" >/etc/security/pwquality.conf.d/99-cis-mut.conf|rm -f /etc/security/pwquality.conf.d/99-cis-mut.conf'
    '5.3.3.1.1|printf "deny = 10\n" >>/etc/security/faillock.conf|sed -i "/^deny = 10$/d" /etc/security/faillock.conf'
    '5.3.3.4.1|sed -i "0,/pam_unix.so/s//pam_unix.so nullok/" /etc/pam.d/common-auth|sed -i "s/pam_unix.so nullok/pam_unix.so/" /etc/pam.d/common-auth'
    '6.1.1.1.6|printf "[Journal]\nStorage=volatile\n" >/etc/systemd/journald.conf.d/99-cis-mut.conf|rm -f /etc/systemd/journald.conf.d/99-cis-mut.conf'
    '6.3.2|systemctl disable --now dailyaidecheck.timer|systemctl enable --now dailyaidecheck.timer'
    '2.3.1.1|systemctl enable --now systemd-timesyncd|systemctl disable --now systemd-timesyncd'
    '1.2.1.12|printf "Acquire::AllowInsecureRepositories \"1\";\n" >/etc/apt/apt.conf.d/99-cis-mut|rm -f /etc/apt/apt.conf.d/99-cis-mut'
    '1.3.1.2|systemctl stop apparmor|systemctl start apparmor'
    '6.1.3.1|touch /var/log/cis-mut.log && chmod 0666 /var/log/cis-mut.log|rm -f /var/log/cis-mut.log'
    '7.2.9|chmod 0777 /root|chmod 0700 /root'
)

state_table() { # state_table <audit args...> -> id<TAB>state lines
    bash "$AUDIT" --no-color --quiet --format text --output "$WORK/out" "$@" >/dev/null 2>&1
    local f
    f=$(ls -t "$WORK"/out/*.txt | head -n1)
    sed -n '/^5. FULL RESULTS/,$p' "$f" | grep -E '^\[[A-Z/]+\] ' | sed -E 's/^\[([A-Z/]+)\] ([0-9.]+) .*/\2\t\1/' | sort
}

ok=0 bad=0
if (( ! FAST )); then
    echo "baseline run ..."
    state_table --no-slow >"$WORK/base.tsv"
fi
for m in "${MUTATIONS[@]}"; do
    IFS='|' read -r ids apply revert <<<"$m"
    first=${ids%%,*}
    [[ -n $ONLY && $first != "$ONLY" && ,$ids, != *,"$ONLY",* ]] && continue
    printf 'mutation %-24s %s\n' "$ids" "$apply"
    bash -c "$apply" >/dev/null 2>&1
    if (( FAST )); then
        state_table --only "$first" >"$WORK/now.tsv"
        if grep -q "^$first"$'\t'FAIL "$WORK/now.tsv"; then ok=$((ok + 1)); echo "  ok: $first FAIL"; else bad=$((bad + 1)); echo "  NOT DETECTED: $first"; fi
    else
        state_table --no-slow >"$WORK/now.tsv"
        flips=$(diff "$WORK/base.tsv" "$WORK/now.tsv" | grep '^>' | cut -f1 | sed 's/^> //' | tr '\n' ',')
        flips=${flips%,}
        want=$(tr ',' '\n' <<<"$ids" | sort | tr '\n' ',')
        got=$(tr ',' '\n' <<<"$flips" | sort | tr '\n' ',')
        if [[ $got == "$want" ]]; then ok=$((ok + 1)); echo "  ok: only $ids changed"; else bad=$((bad + 1)); echo "  MISMATCH: expected ${want%,}, changed ${got%,}"; fi
    fi
    bash -c "$revert" >/dev/null 2>&1
done
printf '\n%d mutations detected as expected, %d not\n' "$ok" "$bad"
(( bad == 0 ))
