#!/usr/bin/env bash
# tests/make_fixtures_fresh.sh - sourced by make_fixtures.sh after the hardened fixture
# exists. Builds "fresh": a default minimal Ubuntu 26.04 Server (the negative baseline).
# SYNTHETIC, like the hardened fixture (see make_fixtures.sh).
# shellcheck disable=SC2154

cp -r "$OUT/hardened" "$OUT/fresh"
F=$OUT/fresh/facts
RF=$OUT/fresh/rootfs
setstat() { # setstat path mode user group [type]
    local tmp
    tmp=$(grep -vP "^\Q$1\E\t" "$F/stat.tsv" || true)
    printf '%s\n' "$tmp" >"$F/stat.tsv"
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5:-f}" >>"$F/stat.tsv"
}
W "$RF/proc/sys/kernel/hostname" <<'EOF'
cis-fresh
EOF
W "$RF/etc/hosts" <<'EOF'
127.0.0.1 localhost
127.0.1.1 cis-fresh
EOF
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
cron	installed	3.0pl1-200
openssh-server	installed	1:10.0p1-5
rsync	installed	3.4.1-1
apport	installed	2.33.0-1
update-notifier-common	installed	3.192
systemd-timesyncd	installed	258-1
telnet	installed	0.17-44
bash	installed	5.3-1
EOF
W "$F/unit_files" <<'EOF'
apparmor.service	enabled	enabled
ufw.service	enabled	enabled
systemd-timesyncd.service	enabled	enabled
cron.service	enabled	enabled
ssh.service	enabled	enabled
rsync.service	enabled	enabled
apport.service	enabled	enabled
systemd-journald.service	static	-
update-notifier-motd.service	static	-
update-notifier-motd.timer	enabled	enabled
EOF
W "$F/units_all" <<'EOF'
apparmor.service loaded active exited Load AppArmor profiles
ufw.service loaded active exited Uncomplicated firewall
systemd-timesyncd.service loaded active running Network Time Synchronization
cron.service loaded active running Regular background program processing daemon
ssh.service loaded active running OpenBSD Secure Shell server
rsync.service loaded active running fast remote file copy program daemon
systemd-journald.service loaded active running Journal Service
update-notifier-motd.timer loaded active waiting Check for a new version of Ubuntu
EOF
W "$F/mounts" <<'EOF'
TARGET="/" SOURCE="/dev/sda2" FSTYPE="ext4" OPTIONS="rw,relatime"
TARGET="/boot" SOURCE="/dev/sda3" FSTYPE="ext4" OPTIONS="rw,relatime"
TARGET="/dev/shm" SOURCE="tmpfs" FSTYPE="tmpfs" OPTIONS="rw,nosuid,nodev"
EOF

# sysctl: kernel defaults while running, only vendor defaults persisted
: >"$F/sysctl_running"
while IFS=$'\t' read -r id title assess srv ws type params applies slow status; do
    [[ $type == sysctl ]] || continue
    key=${params#key=}; key=${key%%;*}
    case $key in
        net.ipv4.conf.*.rp_filter) v=2 ;;
        net.ipv4.conf.*.accept_redirects|net.ipv4.conf.*.secure_redirects|net.ipv4.conf.*.send_redirects) v=1 ;;
        net.ipv4.conf.*.accept_source_route|net.ipv4.conf.*.log_martians) v=0 ;;
        net.ipv4.icmp_ignore_bogus_error_responses|net.ipv4.icmp_echo_ignore_broadcasts|net.ipv4.tcp_syncookies) v=1 ;;
        kernel.randomize_va_space) v=2 ;;
        kernel.kptr_restrict|kernel.yama.ptrace_scope|kernel.dmesg_restrict|fs.protected_hardlinks) v=1 ;;
        fs.suid_dumpable) v=2 ;;
        net.ipv6.conf.*.accept_ra|net.ipv6.conf.*.accept_redirects) v=1 ;;
        *) v=0 ;;
    esac
    printf '%s = %s\n' "$key" "$v" >>"$F/sysctl_running"
done <"$CATALOG"
W "$F/sysctl_cat" <<'EOF'
# /usr/lib/sysctl.d/10-kernel-hardening.conf
kernel.kptr_restrict = 1
kernel.yama.ptrace_scope = 1
# /usr/lib/sysctl.d/50-default.conf
kernel.sysrq = 176
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.rp_filter = 2
net.ipv4.tcp_syncookies = 1
fs.protected_hardlinks = 1
fs.suid_dumpable = 2
EOF
W "$F/sshd_T" <<'EOF'
port 22
addressfamily any
permitrootlogin without-password
pubkeyauthentication yes
passwordauthentication yes
banner none
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
clientaliveinterval 0
clientalivecountmax 3
disableforwarding no
gssapiauthentication no
hostbasedauthentication no
ignorerhosts yes
logingracetime 120
loglevel INFO
maxauthtries 6
maxsessions 10
maxstartups 10:30:100
permitemptypasswords no
permituserenvironment no
usepam yes
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
EOF
: >"$F/modprobe_cfg"
W "$F/ufw_status" <<'EOF'
Status: inactive
EOF
: >"$F/apt_config"
W "$F/apt_policy" <<'EOF'
libpam-runtime:
  Installed: 1.7.0-3
  Candidate: 1.7.0-3ubuntu1
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
EOF
W "$F/catcfg.systemd_coredump.conf" <<'EOF'
# /usr/lib/systemd/coredump.conf
[Coredump]
#Storage=external
#ProcessSizeMax=2G
EOF
: >"$F/ps_chronyd"
W "$F/home_dots" <<'EOF'
home	ubuntu	/home/ubuntu	ext4
f	ubuntu	664	ubuntu	ubuntu	/home/ubuntu/.bashrc
f	ubuntu	644	ubuntu	ubuntu	/home/ubuntu/.profile
f	ubuntu	644	ubuntu	ubuntu	/home/ubuntu/.bash_history
f	ubuntu	600	ubuntu	ubuntu	/home/ubuntu/.netrc
d	ubuntu	775	ubuntu	ubuntu	/home/ubuntu/.config
d	ubuntu	700	ubuntu	ubuntu	/home/ubuntu/.ssh
EOF
printf 'suid\t/usr/bin/sudo\n' >"$F/fs_suid"
W "$F/fs_world" <<'EOF'
f	/srv/scratch.txt
d	/srv/shared
EOF
printf 'u\t/opt/orphan\n' >"$F/fs_nouser"
: >"$F/sudo_log"
W "$F/mta_cfg" <<'EOF'
postconf: inet_interfaces = all
EOF
W "$F/ss_listen" <<'EOF'
tcp   LISTEN 0 4096 0.0.0.0:22     0.0.0.0:*    users:(("sshd",pid=801,fd=3))
tcp   LISTEN 0 100  0.0.0.0:25     0.0.0.0:*    users:(("master",pid=950,fd=13))
udp   UNCONN 0 0    127.0.0.54:53  0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=15))
EOF
W "$F/logfiles" <<'EOF'
644	root	root	/var/log/syslog
640	root	adm	/var/log/auth.log
666	root	root	/var/log/custom.log
EOF
W "$F/apt_keyfiles" <<'EOF'
664	root	root	/usr/share/keyrings/extra.gpg
EOF
W "$RF/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/bash
syslog:x:102:102::/nonexistent:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
ghost:x:1001:9999:Ghost:/home/ghost:/bin/bash
toor:x:0:0:Second root:/root:/bin/bash
EOF
W "$RF/etc/group" <<'EOF'
root:x:0:
daemon:x:1:
adm:x:4:syslog,ubuntu
shadow:x:42:ubuntu
syslog:x:102:
nogroup:x:65534:
ubuntu:x:1000:
ubuntu2:x:1000:
EOF
W "$RF/etc/shadow" <<'EOF'
root:*:20000:0:99999:7:::
daemon:*:20000:0:99999:7:::
bin:*:20000:0:99999:7:::
sync:*:20000:0:99999:7:::
games:::0:99999:7:::
syslog:*:20000:0:99999:7:::
sshd:*:20000:0:99999:7:::
nobody:*:20000:0:99999:7:::
ubuntu:$y$j9T$abcdefghijklmnop$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg:20000:0:99999:7:::
ghost::20000:0:99999:7:::
EOF
W "$RF/etc/login.defs" <<'EOF'
MAIL_DIR        /var/mail
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
UID_MIN                  1000
UMASK           022
ENCRYPT_METHOD YESCRYPT
EOF
W "$RF/etc/default/useradd" <<'EOF'
GROUP=100
HOME=/home
INACTIVE=-1
SHELL=/bin/sh
EOF
rm -f "$RF/etc/security/faillock.conf" "$RF/etc/security/pwhistory.conf" "$RF/etc/security/limits.d/60-cis.conf"
rm -rf "$RF/etc/security/pwquality.conf.d"
W "$RF/etc/security/pwquality.conf" <<'EOF'
# Configuration for systems password quality (all commented in the default install)
# minlen = 8
EOF
W "$RF/etc/pam.d/common-auth" <<'EOF'
auth	[success=1 default=ignore]	pam_unix.so nullok
auth	requisite			pam_deny.so
auth	required			pam_permit.so
EOF
W "$RF/etc/pam.d/common-account" <<'EOF'
account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so
account	requisite			pam_deny.so
account	required			pam_permit.so
EOF
W "$RF/etc/pam.d/common-password" <<'EOF'
password	requisite			pam_pwquality.so retry=3
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt
password	requisite			pam_deny.so
password	required			pam_permit.so
EOF
W "$RF/etc/pam.d/su" <<'EOF'
auth       sufficient pam_rootok.so
@include common-auth
EOF
W "$RF/etc/ssh/sshd_config.d/60-cis.conf" <<'EOF'
EOF
W "$RF/etc/issue" <<'EOF'
Ubuntu 26.04 LTS \n \l
EOF
W "$RF/etc/issue.net" <<'EOF'
Ubuntu 26.04 LTS
EOF
W "$RF/etc/sudoers" <<'EOF'
Defaults	env_reset
Defaults	mail_badpass
root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
EOF
rm -f "$RF/etc/sudoers.d/90-deploy"
W "$RF/etc/profile" <<'EOF'
# /etc/profile
if [ "${PS1-}" ]; then
  PS1='\u@\h:\w\$ '
fi
EOF
rm -f "$RF/etc/profile.d/60-cis-tmout.sh"
W "$RF/boot/grub/grub.cfg" <<'EOF'
menuentry 'Ubuntu' {
	linux	/vmlinuz-6.14.0-30-generic root=/dev/sda2 ro quiet
}
EOF
W "$RF/root/.profile" <<'EOF'
umask 022
EOF
rm -f "$RF/etc/cron.allow" "$RF/etc/chrony/chrony.conf"
W "$RF/etc/ufw/ufw.conf" <<'EOF'
ENABLED=no
LOGLEVEL=low
EOF
W "$RF/etc/apt/sources.list.d/ubuntu.sources" <<'EOF'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: questing
Components: main restricted universe multiverse
EOF
W "$RF/etc/default/apport" <<'EOF'
enabled=1
EOF
setstat /etc/ssh/sshd_config 644 root root
setstat /etc/ssh/sshd_config.d 755 root root d
setstat /etc/ssh/ssh_host_rsa_key 640 root ssh_keys
setstat /etc/crontab 644 root root
for d in hourly daily weekly monthly d; do setstat /etc/cron.$d 755 root root d; done
setstat /boot/grub/grub.cfg 444 root root
setstat /home/ubuntu 755 ubuntu ubuntu d
setstat /etc/security/opasswd 644 root root
setstat /etc/cron.allow - - -        # absent in a default install
rm -rf "$RF/home/deploy"
mkdir -p "$RF/home/ubuntu"
printf 'fresh fixture written to %s\n' "$OUT/fresh"
