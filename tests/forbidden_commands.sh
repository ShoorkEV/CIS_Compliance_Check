#!/usr/bin/env bash
# tests/forbidden_commands.sh - fail when runtime code could change the system.
#
# Scans cis-audit.sh and lib/ (not tools/ or tests/) for the commands the plan
# forbids (section 3): package changes, service state changes, sysctl writes,
# module loading, chmod/chown/chattr, sed -i, anything but `ufw status`, password
# and account tools, AIDE init/update, and redirections into absolute paths other
# than /dev/null. Comment lines are ignored; a command is matched only in command
# position so words in messages do not trigger it.
#
# usage: tests/forbidden_commands.sh [--selftest] [files...]
set -u
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$HERE/..

# command position: start of line, after ; & | ( { $( then do else, or a timeout wrapper
CMD='(?:^\S+:\d+:\s|[;&|]|\{\s|\$\(|\b(?:then|do|else)|\btmo(?:_tol)?|\bslow_tmo|\btimeout(?:\s+-\S+)*\s+\S+)\s*'
declare -a PATTERNS=(
    "${CMD}\\K(?:apt|apt-get|aptitude)\\s+(?:-\\S+\\s+)*(?:install|remove|purge|update|upgrade|dist-upgrade|autoremove|full-upgrade)\\b"
    "${CMD}\\Kdpkg\\s+(?:-\\S+\\s+)*(?:-[iPr]\\b|--(?:install|remove|purge|configure)\\b)"
    "${CMD}\\Ksystemctl\\s+(?:-\\S+\\s+)*(?:start|stop|restart|reload|enable|disable|mask|unmask|daemon-reload|kill|isolate|set-default|edit|link)\\b"
    "${CMD}\\Ksysctl\\s+(?:-\\S+\\s+)*(?:-[wp]\\b|--(?:write|load)\\b)"
    "${CMD}\\Kmodprobe\\b(?!.*(?:\\s-n\\b|--showconfig|--dry-run))"
    "${CMD}\\K(?:insmod|rmmod|depmod)\\b"
    "${CMD}\\Kauditctl\\b(?!\\s+-[ls]\\b)"
    "${CMD}\\K(?:chmod|chown|chgrp|chattr|setfacl|setcap|umount|mount|swapoff|swapon)\\b"
    "${CMD}\\Ksed\\s+(?:-\\S+\\s+)*-[A-Za-z]*i"
    "${CMD}\\Kufw\\s+(?!status\\b)"
    "${CMD}\\K(?:passwd|usermod|useradd|userdel|groupadd|groupdel|gpasswd|chpasswd|adduser|deluser)\\b"
    "${CMD}\\Kchage\\b(?!\\s+(?:-l|--list)\\b)"
    "${CMD}\\Kpam-auth-update\\b"
    "${CMD}\\Kaide(?:init)?\\b.*(?:--init|--update|\\s-[iu]\\b)"
    "${CMD}\\K(?:touch|tee|dd|truncate|shred|ln|install|rsync|curl|wget|nc|ssh|scp)\\s"
    "(?<![&0-9/])>>?\\s*/(?!dev/null\\b|dev/stderr\\b)"
)

# scan_files <files...>: one pass over all files; returns 1 when anything is found
scan_files() {
    local all pat hits rc=0
    all=$(mktemp)
    awk '{ l = $0; sub(/^[ 	]+/, "", l); if (l !~ /^#/) print FILENAME ":" FNR ": " $0 }' "$@" >"$all"
    for pat in "${PATTERNS[@]}"; do
        hits=$(grep -P -- "$pat" "$all" || true)
        if [[ -n $hits ]]; then
            printf 'FORBIDDEN (pattern %s):
%s
' "${pat#"$CMD"}" "$hits"
            rc=1
        fi
    done
    # rm may only remove temp data
    hits=$(grep -P -- "${CMD}\Krm\s" "$all" | grep -vE 'TMPD|FACT_FILE|FACTS_DIR' || true)
    if [[ -n $hits ]]; then
        printf 'FORBIDDEN rm outside the temp dir:
%s
' "$hits"
        rc=1
    fi
    rm -f -- "$all"
    return $rc
}
scan_file() { scan_files "$1"; }

if [[ ${1-} == --selftest ]]; then
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT
    bad=0
    while IFS= read -r line; do
        printf '%s\n' "$line" >"$tmp"
        if scan_file "$tmp" >/dev/null; then
            echo "selftest: not detected: $line"
            bad=1
        fi
    done <<'EOF'
systemctl stop ssh
    apt-get install foo
sysctl -w net.ipv4.ip_forward=1
x=$(modprobe cramfs)
chmod 600 /etc/shadow
sed -i 's/a/b/' /etc/ssh/sshd_config
ufw enable
echo x > /etc/foo
if true; then passwd -l root; fi
tmo auditctl -e 1
rm -rf /etc/cis
EOF
    while IFS= read -r line; do
        printf '%s\n' "$line" >"$tmp"
        if ! scan_file "$tmp" >/dev/null; then
            echo "selftest: false positive: $line"
            bad=1
        fi
    done <<'EOF'
tmo "$BIN" --showconfig
tmo modprobe -n -v foo
systemctl list-unit-files --no-pager
echo "missing 'blacklist $n' in modprobe configuration"
# chmod 600 in a comment
ufw status verbose
x=$(sed -E 's/a/b/' file) 2>/dev/null
rm -rf -- "$TMPD"
printf 'x' >&2
EOF
    (( bad == 0 )) && echo "selftest ok"
    exit "$bad"
fi

files=("$@")
if (( ${#files[@]} == 0 )); then
    files=("$ROOT/cis-audit.sh")
    while IFS= read -r f; do files+=("$f"); done < <(find "$ROOT/lib" -name '*.sh' | sort)
fi
rc=0
scan_files "${files[@]}" || rc=1
if (( rc == 0 )); then echo "no forbidden commands in ${#files[@]} files"; fi
exit "$rc"
