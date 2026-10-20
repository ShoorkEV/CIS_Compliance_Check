#!/usr/bin/env bash
# tests/make_fixtures.sh - regenerate the SYNTHETIC test fixtures in tests/fixtures/.
#
# These fixtures were written by hand to look like (a) a hardened Ubuntu 26.04 server
# and (b) a default minimal install. They were NOT recorded from a real machine.
# Replace them with real captures from the VMs using tools/record_facts.sh (plan section 12).
#
# Layout of a fixture:  <name>/facts/*    command output facts (CIS_AUDIT_FACTS_DIR)
#                       <name>/facts/stat.tsv   file metadata: path mode user group type
#                       <name>/rootfs/*   files read by the checks (CIS_AUDIT_ROOTFS)
set -eu
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUT=$HERE/fixtures
CATALOG=$HERE/../catalog/controls.tsv
rm -rf "$OUT/hardened" "$OUT/fresh" "$OUT/variant"
F=$OUT/hardened/facts
RF=$OUT/hardened/rootfs

W() { mkdir -p "$(dirname -- "$1")"; cat >"$1"; }
S() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-f}" >>"$F/stat.tsv"; }

mkdir -p "$F" "$RF"
: >"$F/stat.tsv"

# ------------------------------------------------------------------ facts ----
W "$F/dpkg" <<'EOF'
apparmor	installed	4.1.0-1
apparmor-utils	installed	4.1.0-1
ufw	installed	0.36.2-9
sudo-rs	installed	0.2.8-1
libpam-runtime	installed	1.7.0-3
libpam-modules	installed	1.7.0-3
libpam-modules-bin	installed	1.7.0-3
libpam-pwquality	installed	1.4.5-5
cracklib-runtime	installed	2.10.3-2
aide	installed	0.19.1-1
aide-common	installed	0.19.1-1
chrony	installed	4.6.1-1
cron	installed	3.0pl1-200
openssh-server	installed	1:10.0p1-5
nginx	installed	1.28.0-1
systemd-coredump	installed	258-1
bash	installed	5.3-1
EOF
W "$F/unit_files" <<'EOF'
apparmor.service	enabled	enabled
ufw.service	enabled	enabled
chrony.service	enabled	enabled
cron.service	enabled	enabled
ssh.service	enabled	enabled
nginx.service	enabled	enabled
systemd-journald.service	static	-
dailyaidecheck.timer	enabled	enabled
dailyaidecheck.service	static	-
tmp.mount	generated	-
update-notifier-motd.service	disabled	enabled
update-notifier-motd.timer	disabled	enabled
EOF
W "$F/units_all" <<'EOF'
apparmor.service loaded active exited Load AppArmor profiles
ufw.service loaded active exited Uncomplicated firewall
chrony.service loaded active running chrony, an NTP client/server
cron.service loaded active running Regular background program processing daemon
ssh.service loaded active running OpenBSD Secure Shell server
nginx.service loaded active running A high performance web server
systemd-journald.service loaded active running Journal Service
dailyaidecheck.timer loaded active waiting Daily AIDE check
EOF
W "$F/mounts" <<'EOF'
TARGET="/" SOURCE="/dev/mapper/vg-root" FSTYPE="ext4" OPTIONS="rw,relatime"
TARGET="/boot" SOURCE="/dev/sda2" FSTYPE="ext4" OPTIONS="rw,relatime"
TARGET="/tmp" SOURCE="tmpfs" FSTYPE="tmpfs" OPTIONS="rw,nosuid,nodev,noexec,relatime"
TARGET="/dev/shm" SOURCE="tmpfs" FSTYPE="tmpfs" OPTIONS="rw,nosuid,nodev,noexec,relatime"
TARGET="/home" SOURCE="/dev/mapper/vg-home" FSTYPE="ext4" OPTIONS="rw,nosuid,nodev,relatime"
TARGET="/var" SOURCE="/dev/mapper/vg-var" FSTYPE="ext4" OPTIONS="rw,nosuid,nodev,relatime"
TARGET="/var/tmp" SOURCE="/dev/mapper/vg-vartmp" FSTYPE="ext4" OPTIONS="rw,nosuid,nodev,noexec,relatime"
TARGET="/var/log" SOURCE="/dev/mapper/vg-varlog" FSTYPE="ext4" OPTIONS="rw,nosuid,nodev,noexec,relatime"
TARGET="/var/log/audit" SOURCE="/dev/mapper/vg-audit" FSTYPE="ext4" OPTIONS="rw,nosuid,nodev,noexec,relatime"
EOF

# sysctl: every key of the catalog with its (first) expected value
: >"$F/sysctl_running"
: >"$F/sysctl_cat"
printf '# /usr/lib/sysctl.d/50-default.conf\nkernel.sysrq = 176\n' >>"$F/sysctl_cat"
printf '# /etc/sysctl.d/60-cis.conf\n' >>"$F/sysctl_cat"
while IFS=$'\t' read -r id title assess srv ws type params applies slow status; do
    [[ $type == sysctl ]] || continue
    key=${params#key=}; key=${key%%;*}
    val=${params#*value=}; val=${val#*values=}; val=${val%%;*}; val=${val%%,*}
    printf '%s = %s\n' "$key" "$val" >>"$F/sysctl_running"
    printf '%s = %s\n' "$key" "$val" >>"$F/sysctl_cat"
done <"$CATALOG"
printf 'kernel.sysrq = 176\nnet.ipv4.conf.all.arp_ignore = 0\n' >>"$F/sysctl_running"

W "$F/sshd_T" <<'EOF'
port 22
addressfamily any
permitrootlogin no
pubkeyauthentication yes
passwordauthentication no
allowusers deploy
banner /etc/issue.net
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
macs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com
clientaliveinterval 15
clientalivecountmax 3
disableforwarding yes
gssapiauthentication no
hostbasedauthentication no
ignorerhosts yes
logingracetime 60
loglevel VERBOSE
maxauthtries 4
maxsessions 10
maxstartups 10:30:60
permitemptypasswords no
permituserenvironment no
usepam yes
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
EOF
W "$F/modprobe_cfg" <<'EOF'
blacklist cramfs
install cramfs /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist firewire_core
install firewire_core /bin/false
blacklist usb_storage
install usb_storage /bin/false
blacklist atm
install atm /bin/false
blacklist can
install can /bin/false
blacklist dccp
install dccp /bin/false
blacklist rds
install rds /bin/false
blacklist sctp
install sctp /bin/false
blacklist tipc
install tipc /bin/false
EOF
W "$F/lsmod" <<'EOF'
Module                  Size  Used by
ext4                 1000000  4
jbd2                  200000  1 ext4
EOF
K=/usr/lib/modules/6.14.0-30-generic/kernel
W "$F/kmod_files" <<EOF
$K/fs/cramfs/cramfs.ko.zst
$K/fs/freevxfs/freevxfs.ko.zst
$K/fs/jffs2/jffs2.ko.zst
$K/fs/ext4/ext4.ko.zst
$K/net/sctp/sctp.ko.zst
$K/net/dccp/dccp_ipv4.ko.zst
$K/net/tipc/tipc.ko.zst
$K/drivers/usb/storage/usb-storage.ko.zst
$K/drivers/firewire/firewire-core.ko.zst
EOF
W "$F/ss_listen" <<'EOF'
tcp   LISTEN 0 4096 0.0.0.0:22     0.0.0.0:*    users:(("sshd",pid=801,fd=3))
tcp   LISTEN 0 511  0.0.0.0:80     0.0.0.0:*    users:(("nginx",pid=905,fd=5))
tcp   LISTEN 0 511  0.0.0.0:443    0.0.0.0:*    users:(("nginx",pid=905,fd=6))
udp   UNCONN 0 0    127.0.0.1:323  0.0.0.0:*    users:(("chronyd",pid=700,fd=5))
EOF
W "$F/ufw_status" <<'EOF'
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
EOF
W "$F/apt_config" <<'EOF'
Acquire::AllowInsecureRepositories "0";
Acquire::AllowWeakRepositories "0";
Acquire::AllowDowngradeToInsecureRepositories "0";
Acquire::Check-Date "true";
APT::Install-Recommends "1";
EOF
W "$F/apt_policy" <<'EOF'
libpam-runtime:
  Installed: 1.7.0-3
  Candidate: 1.7.0-3
  Version table:
 *** 1.7.0-3 500
libpam-modules:
  Installed: 1.7.0-3
  Candidate: 1.7.0-3
libpam-pwquality:
  Installed: 1.4.5-5
  Candidate: 1.4.5-5
cracklib-runtime:
  Installed: 2.10.3-2
  Candidate: 2.10.3-2
EOF
W "$F/catcfg.systemd_journald.conf" <<'EOF'
# /usr/lib/systemd/journald.conf
[Journal]
#Storage=auto
#Compress=yes
#ForwardToSyslog=no

# /etc/systemd/journald.conf.d/60-cis.conf
[Journal]
Storage=persistent
Compress=yes
EOF
W "$F/catcfg.systemd_coredump.conf" <<'EOF'
# /usr/lib/systemd/coredump.conf
[Coredump]
#Storage=external
#ProcessSizeMax=2G

# /etc/systemd/coredump.conf.d/60-cis.conf
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
W "$F/catcfg.systemd_timesyncd.conf" <<'EOF'
# /usr/lib/systemd/timesyncd.conf
[Time]
#NTP=
#FallbackNTP=ntp.ubuntu.com
EOF
W "$F/aa_status" <<'EOF'
apparmor module is loaded.
42 profiles are loaded.
38 profiles are in enforce mode.
EOF
W "$F/ps_chronyd" <<'EOF'
root     /sbin/init
_chrony  /usr/sbin/chronyd -F 1
deploy   -bash
EOF
printf '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' >"$F/root_path"
: >"$F/mta_cfg"
: >"$F/apt_keyfiles"
: >"$F/logfiles"
: >"$F/wireless_modules"
: >"$F/fs_world"
: >"$F/fs_nouser"
printf 'suid\t/usr/bin/sudo\nsuid\t/usr/bin/passwd\nsgid\t/usr/bin/crontab\n' >"$F/fs_suid"
W "$F/home_dots" <<'EOF'
home	deploy	/home/deploy	ext4
f	deploy	600	deploy	deploy	/home/deploy/.bash_history
f	deploy	644	deploy	deploy	/home/deploy/.bashrc
f	deploy	644	deploy	deploy	/home/deploy/.profile
d	deploy	700	deploy	deploy	/home/deploy/.ssh
d	deploy	750	deploy	deploy	/home/deploy/.config
EOF
W "$F/sudo_log" <<'EOF'
Oct 20 09:12:01 host sudo-rs[2201]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/true
EOF

# ------------------------------------------------------------------ rootfs ---
W "$RF/etc/os-release" <<'EOF'
PRETTY_NAME="Ubuntu 26.04 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
ID=ubuntu
EOF
W "$RF/proc/sys/kernel/hostname" <<'EOF'
cis-hardened
EOF
W "$RF/proc/sys/kernel/ostype" <<'EOF'
Linux
EOF
W "$RF/proc/sys/kernel/osrelease" <<'EOF'
6.14.0-30-generic
EOF
W "$RF/proc/cmdline" <<'EOF'
BOOT_IMAGE=/vmlinuz-6.14.0-30-generic root=/dev/mapper/vg-root ro quiet
EOF
W "$RF/sys/module/ipv6/parameters/disable" <<'EOF'
0
EOF
W "$RF/etc/hosts" <<'EOF'
127.0.0.1 localhost
127.0.1.1 cis-hardened.example.org cis-hardened
EOF
W "$RF/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
syslog:x:102:102::/nonexistent:/usr/sbin/nologin
_chrony:x:105:105:Chrony daemon:/var/lib/chrony:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash
EOF
W "$RF/etc/group" <<'EOF'
root:x:0:
daemon:x:1:
bin:x:2:
adm:x:4:syslog
shadow:x:42:
crontab:x:107:
syslog:x:102:
_chrony:x:105:
www-data:x:33:
nogroup:x:65534:
sugroup:x:2000:
deploy:x:1000:
EOF
W "$RF/etc/shadow" <<'EOF'
root:*:20000:0:99999:7:::
daemon:*:20000:0:99999:7:::
bin:*:20000:0:99999:7:::
sync:*:20000:0:99999:7:::
syslog:*:20000:0:99999:7:::
_chrony:*:20000:0:99999:7:::
www-data:*:20000:0:99999:7:::
sshd:*:20000:0:99999:7:::
nobody:*:20000:0:99999:7:::
deploy:$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg:20000:1:365:7:30::
EOF
printf 'root:x::\n' >"$RF/etc/gshadow"
W "$RF/etc/shells" <<'EOF'
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/sh
EOF
W "$RF/etc/login.defs" <<'EOF'
MAIL_DIR        /var/mail
PASS_MAX_DAYS   365
PASS_MIN_DAYS   1
PASS_WARN_AGE   7
UID_MIN                  1000
UMASK           027
ENCRYPT_METHOD YESCRYPT
EOF
W "$RF/etc/default/useradd" <<'EOF'
GROUP=100
HOME=/home
INACTIVE=45
SHELL=/bin/sh
EOF
W "$RF/etc/default/ufw" <<'EOF'
IPT_SYSCTL=/etc/ufw/sysctl.conf
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_FORWARD_POLICY="DROP"
EOF
W "$RF/etc/ufw/ufw.conf" <<'EOF'
ENABLED=yes
LOGLEVEL=low
EOF
W "$RF/etc/ufw/sysctl.conf" <<'EOF'
# ufw sysctl (nothing overridden)
EOF
W "$RF/etc/security/faillock.conf" <<'EOF'
deny = 5
unlock_time = 900
EOF
W "$RF/etc/security/pwquality.conf.d/50-cis.conf" <<'EOF'
difok = 2
minlen = 14
minclass = 3
maxrepeat = 3
maxsequence = 3
dictcheck = 1
enforcing = 1
enforce_for_root
EOF
W "$RF/etc/security/pwhistory.conf" <<'EOF'
remember = 24
enforce_for_root
use_authtok
EOF
W "$RF/etc/security/limits.d/60-cis.conf" <<'EOF'
* hard core 0
EOF
W "$RF/etc/pam.d/common-auth" <<'EOF'
auth	requisite			pam_faillock.so preauth
auth	[success=2 default=ignore]	pam_unix.so try_first_pass
auth	[default=die]			pam_faillock.so authfail
auth	requisite			pam_deny.so
auth	required			pam_permit.so
EOF
W "$RF/etc/pam.d/common-account" <<'EOF'
account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so
account	requisite			pam_deny.so
account	required			pam_faillock.so
EOF
W "$RF/etc/pam.d/common-password" <<'EOF'
password	requisite			pam_pwquality.so retry=3
password	requisite			pam_pwhistory.so
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt
password	requisite			pam_deny.so
password	required			pam_permit.so
EOF
W "$RF/etc/pam.d/common-session" <<'EOF'
session	[default=1]			pam_permit.so
session	requisite			pam_deny.so
session	required			pam_permit.so
session	required	pam_unix.so
EOF
W "$RF/etc/pam.d/common-session-noninteractive" <<'EOF'
session	[default=1]			pam_permit.so
session	requisite			pam_deny.so
session	required			pam_permit.so
session	required	pam_unix.so
EOF
W "$RF/etc/pam.d/su" <<'EOF'
auth       sufficient pam_rootok.so
auth       required   pam_wheel.so use_uid group=sugroup
@include common-auth
EOF
W "$RF/etc/pam.d/sshd" <<'EOF'
@include common-auth
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
EOF
W "$RF/etc/ssh/sshd_config" <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
EOF
W "$RF/etc/ssh/sshd_config.d/60-cis.conf" <<'EOF'
PermitRootLogin no
AllowUsers deploy
EOF
printf 'key\n' >"$RF/etc/ssh/ssh_host_rsa_key"; printf 'key\n' >"$RF/etc/ssh/ssh_host_rsa_key.pub"
printf 'key\n' >"$RF/etc/ssh/ssh_host_ecdsa_key"; printf 'key\n' >"$RF/etc/ssh/ssh_host_ecdsa_key.pub"
printf 'key\n' >"$RF/etc/ssh/ssh_host_ed25519_key"; printf 'key\n' >"$RF/etc/ssh/ssh_host_ed25519_key.pub"
W "$RF/etc/issue" <<'EOF'
Authorized use only. Activity may be monitored and reported.
EOF
cp "$RF/etc/issue" "$RF/etc/issue.net"
W "$RF/etc/sudoers" <<'EOF'
Defaults	env_reset, timestamp_timeout=15
Defaults	use_pty
root	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
EOF
W "$RF/etc/sudoers.d/90-deploy" <<'EOF'
deploy ALL=(ALL) ALL
EOF
W "$RF/etc/chrony/chrony.conf" <<'EOF'
confdir /etc/chrony/conf.d
pool ntp.example.org iburst maxsources 4
sourcedir /etc/chrony/sources.d
EOF
mkdir -p "$RF/etc/chrony/conf.d" "$RF/etc/chrony/sources.d"
W "$RF/etc/apt/sources.list.d/ubuntu.sources" <<'EOF'
Types: deb
URIs: https://archive.ubuntu.com/ubuntu
Suites: questing
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
mkdir -p "$RF/etc/apt/trusted.gpg.d" "$RF/etc/apt/auth.conf.d" "$RF/usr/share/keyrings"
printf 'k\n' >"$RF/usr/share/keyrings/ubuntu-archive-keyring.gpg"
W "$RF/etc/profile" <<'EOF'
# /etc/profile
umask 027
EOF
W "$RF/etc/profile.d/60-cis-tmout.sh" <<'EOF'
readonly TMOUT=900
export TMOUT
EOF
W "$RF/etc/bash.bashrc" <<'EOF'
# system-wide .bashrc
EOF
W "$RF/boot/grub/grub.cfg" <<'EOF'
set superusers="grubadmin"
password_pbkdf2 grubadmin grub.pbkdf2.sha512.10000.AAAAAAAAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBB
menuentry 'Ubuntu' {
	linux	/vmlinuz-6.14.0-30-generic root=/dev/mapper/vg-root ro quiet
}
EOF
W "$RF/root/.profile" <<'EOF'
umask 027
EOF
W "$RF/root/.bashrc" <<'EOF'
# root bashrc
EOF
mkdir -p "$RF/home/deploy" "$RF/etc/cron.hourly" "$RF/etc/cron.daily" "$RF/etc/cron.weekly" "$RF/etc/cron.monthly" "$RF/etc/cron.d"
printf 'k\n' >"$RF/etc/crontab"; printf 'deploy\n' >"$RF/etc/cron.allow"
printf '# 0 = no motd\n' >"$RF/etc/motd" ; rm -f "$RF/etc/motd"
: >"$RF/etc/passwd-"; : >"$RF/etc/group-"; : >"$RF/etc/shadow-"; : >"$RF/etc/gshadow-"
mkdir -p "$RF/etc/security"
: >"$RF/etc/security/opasswd"

# ------------------------------------------------------------------ stat -----
S /etc/passwd 644 root root;   S /etc/passwd- 644 root root
S /etc/group 644 root root;    S /etc/group- 644 root root
S /etc/shadow 640 root shadow; S /etc/shadow- 640 root shadow
S /etc/gshadow 640 root shadow; S /etc/gshadow- 640 root shadow
S /etc/shells 644 root root
S /etc/security/opasswd 600 root root
S /etc/apt/trusted.gpg.d 755 root root d
S /etc/apt/auth.conf.d 755 root root d
S /usr/share/keyrings 755 root root d
S /etc/apt/sources.list.d 755 root root d
S /etc/apt/sources.list.d/ubuntu.sources 644 root root
S /boot/grub/grub.cfg 600 root root
S /etc/issue 644 root root; S /etc/issue.net 644 root root
S /etc/ssh/sshd_config 600 root root
S /etc/ssh/sshd_config.d 700 root root d
S /etc/ssh/sshd_config.d/60-cis.conf 600 root root
for k in rsa ecdsa ed25519; do
    S /etc/ssh/ssh_host_${k}_key 600 root root
    S /etc/ssh/ssh_host_${k}_key.pub 644 root root
done
S /etc/crontab 600 root root
for d in hourly daily weekly monthly d; do S /etc/cron.$d 700 root root d; done
S /etc/cron.allow 640 root crontab
S /home/deploy 750 deploy deploy d
S /root 700 root root d
S /usr/local/sbin 755 root root d; S /usr/local/bin 755 root root d
S /usr/sbin 755 root root d; S /usr/bin 755 root root d
S /sbin 755 root root d; S /bin 755 root root d
# synthetic MOTD scripts the way a hardened host would keep them
S /etc/update-motd.d 755 root root d

printf 'hardened fixture written to %s\n' "$OUT/hardened"

# shellcheck source=make_fixtures_fresh.sh
source "$HERE/make_fixtures_fresh.sh"

# shellcheck source=make_fixtures_variant.sh
source "$HERE/make_fixtures_variant.sh"
