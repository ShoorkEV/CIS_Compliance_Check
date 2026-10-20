# Check type, parameters, applicability and slow flag for each Level 1 - Server
# recommendation. Thresholds come from the benchmark PDF audit text; the control ID
# next to a value is the place to verify it. "@NAME:default" means the value may be
# tightened (never loosened) through NAME in site.conf.
#
# Format: id -> (check_type, params, applies_if, slow)

S = {}


def add(i, t, params="", applies="", slow=0):
    S[i] = (t, params, applies, slow)


# ---- 1.1.1.x kernel modules (dir = module directory below /usr/lib/modules/*/kernel/)
for i, name, d in [
    ("1.1.1.1", "cramfs", "fs/cramfs"), ("1.1.1.2", "freevxfs", "fs/freevxfs"),
    ("1.1.1.3", "hfs", "fs/hfs"), ("1.1.1.4", "hfsplus", "fs/hfsplus"),
    ("1.1.1.5", "jffs2", "fs/jffs2"), ("1.1.1.9", "firewire_core", "drivers/firewire"),
    ("1.1.1.10", "usb_storage", "drivers/usb/storage"),
    ("3.2.1", "atm", "net/atm"), ("3.2.2", "can", "net/can"), ("3.2.3", "dccp", "net/dccp"),
    ("3.2.4", "rds", "net/rds"), ("3.2.5", "sctp", "net/sctp"), ("3.2.6", "tipc", "net/tipc"),
]:
    add(i, "kmod_unavailable", f"name={name};dir={d}")

# ---- 1.1.2.x mounts
add("1.1.2.1.1", "mount_tmpfs_or_separate", "path=/tmp;unit=tmp.mount")
add("1.1.2.2.1", "mount_tmpfs_or_separate", "path=/dev/shm")
for base, path, opts in [
    ("1.1.2.1", "/tmp", ["nodev", "nosuid", "noexec"]),
    ("1.1.2.2", "/dev/shm", ["nodev", "nosuid", "noexec"]),
    ("1.1.2.3", "/home", ["nodev", "nosuid"]),
    ("1.1.2.4", "/var", ["nodev", "nosuid"]),
    ("1.1.2.5", "/var/tmp", ["nodev", "nosuid", "noexec"]),
    ("1.1.2.6", "/var/log", ["nodev", "nosuid", "noexec"]),
    ("1.1.2.7", "/var/log/audit", ["nodev", "nosuid", "noexec"]),
]:
    first = 2 if base not in ("1.1.2.1", "1.1.2.2") else 2
    for n, o in enumerate(opts):
        add(f"{base}.{first + n}", "mount_opt", f"path={path};opt={o}")

# ---- 1.2.1 apt
add("1.2.1.3", "custom")
add("1.2.1.4", "file_perm", "path=/etc/apt/trusted.gpg.d;mode=755;owner=root;group=root;missing=fail")
add("1.2.1.5", "file_perm", "path=/etc/apt/auth.conf.d;mode=755;owner=root;group=root;missing=pass")
add("1.2.1.6", "file_perm_glob", "dir=/etc/apt/auth.conf.d;pattern=*;mode=640;owner=root;group=root;missing=pass")
add("1.2.1.7", "file_perm", "path=/usr/share/keyrings;mode=755;owner=root;group=root;missing=fail")
add("1.2.1.8", "file_perm", "path=/etc/apt/sources.list.d;mode=755;owner=root;group=root;missing=fail")
add("1.2.1.9", "file_perm_glob", "dir=/etc/apt/sources.list.d;pattern=*;mode=644;owner=root;group=root;missing=pass")
add("1.2.1.10", "custom")
add("1.2.1.11", "custom")
add("1.2.1.12", "apt_config", "key=Acquire::AllowInsecureRepositories;value=0;accept=0,false,no")
add("1.2.1.13", "apt_config", "key=Acquire::AllowWeakRepositories;value=0;accept=0,false,no")
add("1.2.1.14", "apt_config", "key=Acquire::AllowDowngradeToInsecureRepositories;value=0;accept=0,false,no")
add("1.2.1.15", "apt_config", "key=Acquire::Check-Date;value=true;accept=true,1,yes")

# ---- 1.3 / 1.4 / 1.5
add("1.3.1.1", "pkg_installed", "pkgs=apparmor,apparmor-utils")
add("1.3.1.2", "custom")
add("1.4.1", "custom")
add("1.4.2", "file_perm", "path=/boot/grub/grub.cfg;mode=600;owner=root;group=root;missing=fail")
add("1.5.6", "pkg_absent", "pkgs=prelink")
add("1.5.7", "custom")
add("1.5.10", "custom")
add("1.5.11", "conf_kv", "src=catcfg:systemd/coredump.conf;section=Coredump;key=ProcessSizeMax;op=eq;value=0;absent=default", "HAS_COREDUMP=1")
add("1.5.12", "conf_kv", "src=catcfg:systemd/coredump.conf;section=Coredump;key=Storage;op=eq;value=none;absent=default", "HAS_COREDUMP=1")

# ---- 1.6 banners
for i in ("1.6.1", "1.6.2", "1.6.3", "1.6.4"):
    add(i, "custom")
add("1.6.5", "sshd_param", "key=banner;op=banner")
add("1.6.6", "file_perm", "path=/etc/motd,/run/motd,/usr/lib/motd,/etc/motd.d/*,/run/motd.d/*,/usr/lib/motd.d/*,/etc/update-motd.d/*;mode=644;owner=root;group=root;missing=pass")
add("1.6.7", "file_perm", "path=/etc/issue,/usr/lib/issue.d/*,/etc/issue.d/*,/run/issue.d/*;mode=644;owner=root;group=root;missing=pass")
add("1.6.8", "file_perm", "path=/etc/issue.net;mode=644;owner=root;group=root;missing=pass")
add("1.6.9", "file_perm", "dyn=pam_motd;mode=644;owner=root;group=root;missing=pass")
add("1.6.10", "file_perm", "dyn=sshd_banner;mode=644;owner=root;group=root;missing=pass")
add("1.6.11", "svc_not_in_use", "units=update-notifier-motd.service")
add("1.6.12", "svc_not_in_use", "units=update-notifier-motd.timer")
for n in range(1, 7):
    add(f"1.7.{n}", "gdm", f"key=gdm_{n}", "HAS_GDM=1")

# ---- 2.1 services
for i, pk, un in [
    ("2.1.1", "autofs", "autofs.service"),
    ("2.1.2", "avahi-daemon", "avahi-daemon.socket,avahi-daemon.service"),
    ("2.1.3", "kea,kea-*", "kea-dhcp-ddns-server.service,kea-dhcp4-server.service,kea-dhcp6-server.service"),
    ("2.1.4", "bind9", "named.service"),
    ("2.1.5", "dnsmasq", "dnsmasq.service"),
    ("2.1.6", "vsftpd", "vsftpd.service"),
    ("2.1.7", "slapd", "slapd.service"),
    ("2.1.8", "dovecot-imapd,dovecot-pop3d", "dovecot.socket,dovecot.service"),
    ("2.1.9", "nfs-kernel-server", "nfs-server.service"),
    ("2.1.10", "ypserv", "ypserv.service"),
    ("2.1.11", "cups", "cups.socket,cups.service"),
    ("2.1.12", "rpcbind", "rpcbind.socket,rpcbind.service"),
    ("2.1.13", "rsync", "rsync.service"),
    ("2.1.14", "samba", "smbd.service"),
    ("2.1.15", "snmpd", "snmpd.service"),
    ("2.1.16", "telnetd,telnetd-ssl", "inetutils-inetd.service"),
    ("2.1.17", "tftpd-hpa", "tftpd-hpa.service"),
    ("2.1.18", "squid", "squid.service"),
    ("2.1.19", "apache2,nginx", "apache2.socket,apache2.service,nginx.service"),
    ("2.1.20", "xinetd", "xinetd.service"),
    ("3.1.3", "bluez", "bluetooth.service"),
]:
    add(i, "svc_not_in_use", f"pkgs={pk};units={un}")
add("6.1.1.1.2", "svc_not_in_use", "units=systemd-journal-remote.socket,systemd-journal-remote.service")
add("2.1.22", "custom")
add("2.1.23", "manual", "hint=List the listening sockets (ss -plntu) and confirm each service, port and interface is required and approved by site policy; compare with APPROVED_LISTENERS in site.conf")

# ---- 2.2 clients
for i, pk in [
    ("2.2.1", "nis"), ("2.2.2", "rsh-client"), ("2.2.3", "talk"),
    ("2.2.4", "telnet,inetutils-telnet,telnet-ssl"), ("2.2.5", "ldap-utils"),
    ("2.2.6", "ftp,tnftp,atftp,inetutils-ftp,ftp-ssl"),
]:
    add(i, "pkg_absent", f"pkgs={pk}")

# ---- 2.3 time sync
add("2.3.1.1", "custom")
add("2.3.2.1", "conf_kv", "src=catcfg:systemd/timesyncd.conf;section=Time;key=NTP;altkey=NTP,FallbackNTP;op=set", "TIME_DAEMON~timesyncd")
add("2.3.2.2", "svc_enabled_active", "unit=systemd-timesyncd.service;need=enabled,active", "TIME_DAEMON~timesyncd")
add("2.3.3.1", "custom", "", "TIME_DAEMON~chrony")
add("2.3.3.2", "custom", "", "TIME_DAEMON~chrony")
add("2.3.3.3", "svc_enabled_active", "unit=chrony.service;need=enabled,active", "TIME_DAEMON~chrony")

# ---- 2.4 cron / at
add("2.4.1.1", "svc_enabled_active", "unit=cron.service|crond.service;need=enabled,active", "HAS_CRON=1")
add("2.4.1.2", "file_perm", "path=/etc/crontab;mode=700;owner=root;group=root;missing=fail", "HAS_CRON=1")
for i, d in [("2.4.1.3", "hourly"), ("2.4.1.4", "daily"), ("2.4.1.5", "weekly"), ("2.4.1.6", "monthly")]:
    add(i, "file_perm", f"path=/etc/cron.{d};mode=700;owner=root;group=root;missing=fail", "HAS_CRON=1")
add("2.4.1.7", "file_perm", "path=/etc/cron.yearly;mode=700;owner=root;group=root;missing=pass", "HAS_CRON=1")
add("2.4.1.8", "file_perm", "path=/etc/cron.d;mode=700;owner=root;group=root;missing=fail", "HAS_CRON=1")
add("2.4.1.9", "custom", "", "HAS_CRON=1")
add("2.4.2.1", "custom", "", "HAS_AT=1")

# ---- 3 network
add("3.1.1", "manual", "hint=Confirm whether IPv6 is meant to be enabled on this host; the sysctl rules 3.3.2.x apply only when it is")
add("3.1.2", "custom")
add("3.2.7", "manual", "hint=Compare the network protocol modules available to the running kernel with the site's documented list of unneeded protocols and confirm each is blacklisted and set to /bin/false or /bin/true")

SYSCTL = [
    ("1.3.1.4", "kernel.apparmor_restrict_unprivileged_unconfined", "1"),
    ("1.5.1", "fs.protected_hardlinks", "1"),
    ("1.5.3", "kernel.yama.ptrace_scope", "1,2,3"),
    ("1.5.4", "fs.suid_dumpable", "0"),
    ("1.5.5", "kernel.dmesg_restrict", "1"),
    ("1.5.8", "kernel.kptr_restrict", "1,2"),
    ("1.5.9", "kernel.randomize_va_space", "2"),
    ("3.3.1.1", "net.ipv4.ip_forward", "0"),
    ("3.3.1.2", "net.ipv4.conf.all.forwarding", "0"),
    ("3.3.1.3", "net.ipv4.conf.default.forwarding", "0"),
    ("3.3.1.4", "net.ipv4.conf.all.send_redirects", "0"),
    ("3.3.1.5", "net.ipv4.conf.default.send_redirects", "0"),
    ("3.3.1.6", "net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("3.3.1.7", "net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("3.3.1.8", "net.ipv4.conf.all.accept_redirects", "0"),
    ("3.3.1.9", "net.ipv4.conf.default.accept_redirects", "0"),
    ("3.3.1.10", "net.ipv4.conf.all.secure_redirects", "0"),
    ("3.3.1.11", "net.ipv4.conf.default.secure_redirects", "0"),
    ("3.3.1.12", "net.ipv4.conf.all.rp_filter", "1"),
    ("3.3.1.13", "net.ipv4.conf.default.rp_filter", "1"),
    ("3.3.1.14", "net.ipv4.conf.all.accept_source_route", "0"),
    ("3.3.1.15", "net.ipv4.conf.default.accept_source_route", "0"),
    ("3.3.1.16", "net.ipv4.conf.all.log_martians", "1"),
    ("3.3.1.17", "net.ipv4.conf.default.log_martians", "1"),
    ("3.3.1.18", "net.ipv4.tcp_syncookies", "1"),
    ("3.3.1.19", "net.ipv4.conf.all.route_localnet", "0"),
    ("3.3.2.1", "net.ipv6.conf.all.forwarding", "0"),
    ("3.3.2.2", "net.ipv6.conf.default.forwarding", "0"),
    ("3.3.2.3", "net.ipv6.conf.all.accept_redirects", "0"),
    ("3.3.2.4", "net.ipv6.conf.default.accept_redirects", "0"),
    ("3.3.2.5", "net.ipv6.conf.all.accept_source_route", "0"),
    ("3.3.2.6", "net.ipv6.conf.default.accept_source_route", "0"),
    ("3.3.2.7", "net.ipv6.conf.all.accept_ra", "0"),
    ("3.3.2.8", "net.ipv6.conf.default.accept_ra", "0"),
]
for i, k, v in SYSCTL:
    kind = "values" if "," in v else "value"
    add(i, "sysctl", f"key={k};{kind}={v}", "IPV6_ENABLED=1" if i.startswith("3.3.2.") else "")

# ---- 4 firewall
add("4.1.1", "pkg_installed", "pkgs=ufw")
for i in ("4.1.2", "4.1.3", "4.1.5"):
    add(i, "custom")

# ---- 5.1 sshd
add("5.1.1", "file_perm", "path=/etc/ssh/sshd_config,/etc/ssh/sshd_config.d/*.conf;mode=600;owner=root;group=root;missing=fail")
add("5.1.2", "file_perm", "path=/etc/ssh/sshd_config.d;mode=700;owner=root;group=root;missing=fail")
add("5.1.3", "file_perm_glob", "source=sshd_hostkey;mode=600;owner=root;group=root")
add("5.1.4", "file_perm_glob", "source=sshd_hostkey;suffix=.pub;mode=644;owner=root;group=root")
add("5.1.5", "sshd_param", "key=allowusers,allowgroups,denyusers,denygroups;op=anyset")
add("5.1.6", "sshd_param", "key=banner;op=banner")
add("5.1.7", "sshd_param", "key=ciphers;op=none_of;value=3des-cbc,blowfish-cbc,cast128-cbc,aes128-cbc,aes192-cbc,aes256-cbc,arcfour,arcfour128,arcfour256,rijndael-cbc@lysator.liu.se")
add("5.1.8", "sshd_param", "key=clientaliveinterval;op=gt;value=0;key2=clientalivecountmax;op2=gt;value2=0")
add("5.1.9", "sshd_param", "key=disableforwarding;op=eq;value=yes")
add("5.1.10", "sshd_param", "key=gssapiauthentication;op=eq;value=no")
add("5.1.11", "sshd_param", "key=hostbasedauthentication;op=eq;value=no")
add("5.1.12", "sshd_param", "key=ignorerhosts;op=eq;value=yes")
add("5.1.13", "sshd_param", "key=kexalgorithms;op=none_of;value=diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1")
add("5.1.14", "manual", "hint=Confirm the post-quantum key exchange algorithms sntrup761x25519-sha512 (and mlkem768x25519-sha256 from OpenSSH 9.9) are offered in KexAlgorithms")
add("5.1.15", "sshd_param", "key=logingracetime;op=range1;value=@SSH_LOGIN_GRACE_TIME:60")
add("5.1.16", "sshd_param", "key=loglevel;op=oneof;value=verbose,info")
add("5.1.17", "sshd_param", "key=macs;op=none_of;value=hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com")
add("5.1.18", "sshd_param", "key=maxauthtries;op=le;value=@SSH_MAX_AUTH_TRIES:4")
add("5.1.19", "sshd_param", "key=maxsessions;op=le;value=@SSH_MAX_SESSIONS:10")
add("5.1.20", "sshd_param", "key=maxstartups;op=maxstartups;value=10:30:60")
add("5.1.21", "sshd_param", "key=permitemptypasswords;op=eq;value=no")
add("5.1.22", "sshd_param", "key=permitrootlogin;op=eq;value=no")
add("5.1.23", "sshd_param", "key=permituserenvironment;op=eq;value=no")
add("5.1.24", "sshd_param", "key=usepam;op=eq;value=yes")

# ---- 5.2 sudo
add("5.2.1", "pkg_installed", "pkgs=sudo-rs|sudo;alt=libsss-sudo,sssd")
for i in ("5.2.2", "5.2.3", "5.2.5", "5.2.6", "5.2.7"):
    add(i, "custom")

# ---- 5.3 PAM
for i, p in [("5.3.1.1", "libpam-runtime"), ("5.3.1.2", "libpam-modules"),
             ("5.3.1.3", "libpam-pwquality"), ("5.3.1.4", "cracklib-runtime")]:
    add(i, "pkg_installed", f"pkgs={p};latest=1")
add("5.3.2.1", "pam_module", "mode=present_all;module=pam_unix.so;files=common-account,common-auth,common-password,common-session,common-session-noninteractive")
add("5.3.2.2", "pam_module", "mode=present_all;module=pam_faillock.so;files=common-auth,common-account;args=common-auth:preauth|common-auth:authfail")
add("5.3.2.3", "pam_module", "mode=present_all;module=pam_pwquality.so;files=common-password")
add("5.3.2.4", "pam_module", "mode=present_all;module=pam_pwhistory.so;files=common-password")
FL = "src=files:/etc/security/faillock.conf;pam_file=common-auth;pam_mod=pam_faillock.so;pam_type=auth"
add("5.3.3.1.1", "conf_kv", FL + ";key=deny;op=range1;value=@FAILLOCK_DENY:5;absent=fail")
add("5.3.3.1.2", "conf_kv", FL + ";key=unlock_time;op=zero_or_ge;value=@FAILLOCK_UNLOCK_TIME:900;absent=fail")
PW = "src=files:/etc/security/pwquality.conf.d/*.conf,/etc/security/pwquality.conf;pam_file=common-password;pam_mod=pam_pwquality.so;pam_type=password"
add("5.3.3.2.1", "conf_kv", PW + ";key=difok;op=ge;value=@PWQ_DIFOK:2;absent=fail")
add("5.3.3.2.2", "conf_kv", PW + ";key=minlen;op=ge;value=@PWQ_MINLEN:14;absent=fail")
add("5.3.3.2.3", "manual", "hint=Confirm minclass and the dcredit/ucredit/lcredit/ocredit settings (none greater than 0) follow site policy and are not overridden on the pam_pwquality line")
add("5.3.3.2.4", "conf_kv", PW + ";key=maxrepeat;op=range;value=1-3;absent=fail")
add("5.3.3.2.5", "conf_kv", PW + ";key=maxsequence;op=range;value=1-3;absent=fail")
add("5.3.3.2.6", "conf_kv", PW + ";key=dictcheck;op=ne;value=0;absent=pass")
add("5.3.3.2.7", "conf_kv", PW + ";key=enforcing;op=ne;value=0;absent=pass")
add("5.3.3.2.8", "conf_kv", "src=files:/etc/security/pwquality.conf.d/*.conf,/etc/security/pwquality.conf;key=enforce_for_root;op=flag;absent=fail")
PH = "mode=conf_or_arg;module=pam_pwhistory.so;conf=/etc/security/pwhistory.conf"
add("5.3.3.3.1", "pam_module", PH + ";key=remember;op=ge;value=@PWHISTORY_REMEMBER:24")
add("5.3.3.3.2", "pam_module", PH + ";key=enforce_for_root;op=flag")
add("5.3.3.3.3", "pam_module", PH + ";key=use_authtok;op=flag")
PU = "module=pam_unix.so"
PUF = "files=common-password,common-auth,common-account,common-session,common-session-noninteractive"
add("5.3.3.4.1", "pam_module", f"mode=forbid_arg;{PU};{PUF};argre=nullok")
add("5.3.3.4.2", "pam_module", f"mode=forbid_arg;{PU};{PUF};argre=remember=\\d+")
add("5.3.3.4.3", "pam_module", f"mode=require_arg;{PU};files=common-password;type=password;argre=sha512|yescrypt")
add("5.3.3.4.4", "pam_module", f"mode=require_arg;{PU};files=common-password;type=password;argre=use_authtok")

# ---- 5.4 accounts
for i in ("5.4.1.1", "5.4.1.3", "5.4.1.4", "5.4.1.5", "5.4.1.6", "5.4.2.1", "5.4.2.2", "5.4.2.3",
          "5.4.2.4", "5.4.2.5", "5.4.2.6", "5.4.2.7", "5.4.2.8", "5.4.3.2", "5.4.3.3"):
    add(i, "custom")

# ---- 6 logging
add("6.1.1.1.1", "svc_enabled_active", "unit=systemd-journald.service;need=active")
add("6.1.1.1.3", "conf_kv", "src=catcfg:systemd/journald.conf;section=Journal;key=ForwardToSyslog;op=eq;value=yes;units_active=systemd-journald.service,rsyslog.service", "LOGGER=rsyslog")
add("6.1.1.1.4", "manual", "hint=Review the journald log file modes defined through tmpfiles.d (0640 or more restrictive) against site policy")
add("6.1.1.1.5", "manual", "hint=Confirm journald log rotation limits (SystemMaxUse, SystemKeepFree, RuntimeMaxUse, RuntimeKeepFree, MaxFileSec) follow site policy")
add("6.1.1.1.6", "conf_kv", "src=catcfg:systemd/journald.conf;section=Journal;key=Storage;op=eq;value=persistent;absent=default")
add("6.1.1.1.7", "conf_kv", "src=catcfg:systemd/journald.conf;section=Journal;key=Compress;op=eq;value=yes;absent=default")
add("6.1.2.1", "pkg_installed", "pkgs=rsyslog", "LOGGER=rsyslog")
add("6.1.2.2", "svc_enabled_active", "unit=rsyslog.service;need=enabled,active", "LOGGER=rsyslog")
add("6.1.2.3", "custom", "", "LOGGER=rsyslog")
add("6.1.2.4", "manual", "hint=Review /etc/rsyslog.conf and /etc/rsyslog.d/*.conf and the files in /var/log to confirm the logging rules match site policy", "LOGGER=rsyslog")
add("6.1.2.5", "manual", "hint=Confirm logs are forwarded to the central log host required by site policy (basic or advanced rsyslog action)", "LOGGER=rsyslog")
add("6.1.2.6", "custom", "", "LOGGER=rsyslog")
add("6.1.2.7", "manual", "hint=Review /etc/logrotate.conf and /etc/logrotate.d/* and confirm log rotation follows site policy", "LOGGER=rsyslog")
add("6.1.3.1", "custom", "", "", 1)
add("6.3.1", "pkg_installed", "pkgs=aide,aide-common")
add("6.3.2", "custom")

# ---- 7 maintenance
for i, p, m, g in [
    ("7.1.1", "/etc/passwd", "644", "root"), ("7.1.2", "/etc/passwd-", "644", "root"),
    ("7.1.3", "/etc/group", "644", "root"), ("7.1.4", "/etc/group-", "644", "root"),
    ("7.1.5", "/etc/shadow", "640", "root|shadow"), ("7.1.6", "/etc/shadow-", "640", "root|shadow"),
    ("7.1.7", "/etc/gshadow", "640", "root|shadow"), ("7.1.8", "/etc/gshadow-", "640", "root|shadow"),
    ("7.1.9", "/etc/shells", "644", "root"),
]:
    miss = "pass" if i in ("7.1.2", "7.1.4", "7.1.6", "7.1.8") else "fail"
    add(i, "file_perm", f"path={p};mode={m};owner=root;group={g};missing={miss}")
add("7.1.10", "file_perm", "path=/etc/security/opasswd,/etc/security/opasswd.old;mode=600;owner=root;group=root;missing=pass")
add("7.1.11", "custom", "", "", 1)
add("7.1.12", "custom", "", "", 1)
add("7.1.13", "manual", "hint=Review the list of SUID and SGID files for programs that are not expected on this host; APPROVED_SUID_FILE in site.conf can hold the approved list", "", 1)
for i in ("7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6", "7.2.7", "7.2.8", "7.2.9", "7.2.10", "7.2.11"):
    add(i, "custom")

# ---- 1.1.1.11 / 1.2.1.1 / 1.2.2.1 manual
add("1.1.1.11", "manual", "hint=Review the filesystem kernel modules available, loaded and mounted on this host and confirm every unused one is blacklisted and set to /bin/false or /bin/true; disabling a module in use can be fatal")
add("1.2.1.1", "manual", "hint=Confirm every deb/deb-src entry and every deb822 stanza names a Signed-By key")
add("1.2.2.1", "manual", "hint=Confirm no updates are pending and no reboot is required; this audit does not run apt update (no network access)")
