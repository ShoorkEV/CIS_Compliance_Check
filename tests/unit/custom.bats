#!/usr/bin/env bats
# Custom checks (cus_<id>): the hardened fixture passes, a targeted mutation fails.

load helpers

# ---- section 1 -----------------------------------------------------------------------
@test "1.2.1.3: key files in the keyring directories must be 0644 or stricter" {
    fx hardened
    check 1.2.1.3
    assert_state 1.2.1.3 PASS
    printf '664\troot\troot\t/usr/share/keyrings/extra.gpg\n' >"$FACTS/apt_keyfiles"
    check 1.2.1.3
    assert_state 1.2.1.3 FAIL
}

@test "1.2.1.3: Signed-By key files outside the standard directories are checked" {
    fx hardened
    printf 'Types: deb\nURIs: https://x.example/\nSuites: a\nSigned-By: /etc/keyrings/x.gpg\n' >"$RFS/etc/apt/sources.list.d/x.sources"
    printf 'k\n' >"$RFS/etc/keyrings/x.gpg" 2>/dev/null || { mkdir -p "$RFS/etc/keyrings"; printf 'k\n' >"$RFS/etc/keyrings/x.gpg"; }
    sset /etc/keyrings/x.gpg 666 root root
    check 1.2.1.3
    assert_state 1.2.1.3 FAIL
}

@test "1.2.1.10 / 1.2.1.11: plain http repositories fail, in .list and deb822 files" {
    fx hardened
    audit --only 1.2.1.10,1.2.1.11
    assert_state 1.2.1.10 PASS
    assert_state 1.2.1.11 PASS
    printf 'deb [signed-by=/k.gpg] http://archive.example/ubuntu questing main\n' >"$RFS/etc/apt/sources.list"
    printf 'Types: deb\nURIs: https://a.example/ http://b.example/\nSuites: a\n' >"$RFS/etc/apt/sources.list.d/x.sources"
    audit --only 1.2.1.10,1.2.1.11
    assert_state 1.2.1.10 FAIL
    assert_state 1.2.1.11 FAIL
}

@test "1.3.1.2: AppArmor disabled on the kernel command line or not loaded fails" {
    fx hardened
    check 1.3.1.2
    assert_state 1.3.1.2 PASS
    sed -i 's/quiet/quiet apparmor=0/' "$RFS/boot/grub/grub.cfg"
    check 1.3.1.2
    assert_state 1.3.1.2 FAIL
    fx hardened
    printf '0 profiles are loaded.\n' >"$FACTS/aa_status"
    check 1.3.1.2
    assert_state 1.3.1.2 FAIL
}

@test "1.4.1: bootloader needs superusers and a password hash" {
    fx hardened
    check 1.4.1
    assert_state 1.4.1 PASS
    sed -i '/password_pbkdf2/d' "$RFS/boot/grub/grub.cfg"
    check 1.4.1
    assert_state 1.4.1 FAIL
}

@test "1.5.7: apport must not be enabled or active" {
    fx hardened
    check 1.5.7
    assert_state 1.5.7 PASS
    printf 'apport\tinstalled\t2\n' >>"$FACTS/dpkg"
    mkdir -p "$RFS/etc/default"
    printf 'enabled=1\n' >"$RFS/etc/default/apport"
    check 1.5.7
    assert_state 1.5.7 FAIL
    printf 'enabled=0\n' >"$RFS/etc/default/apport"
    check 1.5.7
    assert_state 1.5.7 PASS
}

@test "1.5.10: hard core 0 must exist and nothing may exceed 0" {
    fx hardened
    check 1.5.10
    assert_state 1.5.10 PASS
    rm "$RFS/etc/security/limits.d/60-cis.conf"
    check 1.5.10
    assert_state 1.5.10 FAIL
    printf '* hard core 1048576\n' >"$RFS/etc/security/limits.conf"
    check 1.5.10
    assert_state 1.5.10 FAIL
}

@test "1.6.1 - 1.6.3: banner files must not reveal the OS" {
    fx hardened
    audit --only 1.6.1,1.6.2,1.6.3
    assert_state 1.6.1 PASS
    assert_state 1.6.2 PASS
    assert_state 1.6.3 PASS
    printf 'Welcome to \\s \\r\n' >"$RFS/etc/issue"
    printf 'Ubuntu server\n' >"$RFS/etc/issue.net"
    mkdir -p "$RFS/etc/motd.d"
    printf 'Kernel \\v\n' >"$RFS/etc/motd.d/10-info"
    audit --only 1.6.1,1.6.2,1.6.3
    assert_state 1.6.1 FAIL
    assert_state 1.6.2 FAIL
    assert_state 1.6.3 FAIL
}

@test "1.6.2 / 1.6.3: BANNER_FILE from site.conf must match exactly" {
    fx hardened
    printf 'Other text\n' >"$FX/banner.txt"
    printf 'BANNER_FILE=%s\n' "/banner-not-under-root" >"$FX/site.conf"
    cp "$FX/banner.txt" "$RFS/banner-not-under-root"
    audit --only 1.6.2,1.6.3 --config "$FX/site.conf"
    assert_state 1.6.2 FAIL
    cp "$RFS/etc/issue" "$RFS/banner-not-under-root"
    audit --only 1.6.2 --config "$FX/site.conf"
    assert_state 1.6.2 PASS
}

@test "1.6.4: a pam_motd file with OS information fails" {
    fx hardened
    check 1.6.4
    assert_state 1.6.4 PASS
    printf 'Ubuntu 26.04\n' >"$RFS/run/motd.dynamic" 2>/dev/null || { mkdir -p "$RFS/run"; printf 'Ubuntu 26.04\n' >"$RFS/run/motd.dynamic"; }
    check 1.6.4
    assert_state 1.6.4 FAIL
}

@test "1.6.9 / 1.6.10: pam_motd and sshd banner files are checked when they exist" {
    fx hardened
    mkdir -p "$RFS/run"
    printf 'x\n' >"$RFS/run/motd.dynamic"
    sset /run/motd.dynamic 666 root root
    sset /etc/issue.net 666 root root
    audit --only 1.6.9,1.6.10
    assert_state 1.6.9 FAIL
    assert_state 1.6.10 FAIL
}

# ---- section 2 -----------------------------------------------------------------------
@test "2.1.22: a mail server listening on a non-loopback address fails" {
    fx hardened
    check 2.1.22
    assert_state 2.1.22 PASS
    printf 'tcp LISTEN 0 100 0.0.0.0:25 0.0.0.0:* users:(("master",pid=1,fd=1))\n' >>"$FACTS/ss_listen"
    check 2.1.22
    assert_state 2.1.22 FAIL
}

@test "2.1.22: loopback listeners and a loopback-only Postfix pass" {
    fx hardened
    printf 'tcp LISTEN 0 100 127.0.0.1:25 0.0.0.0:* users:(("master",pid=1,fd=1))\ntcp LISTEN 0 100 [::1]:25 [::]:* users:(("master",pid=1,fd=2))\n' >>"$FACTS/ss_listen"
    printf 'postconf: inet_interfaces = loopback-only\n' >"$FACTS/mta_cfg"
    check 2.1.22
    assert_state 2.1.22 PASS
    printf 'postconf: inet_interfaces = all\n' >"$FACTS/mta_cfg"
    check 2.1.22
    assert_state 2.1.22 FAIL
    printf 'postconf: inet_interfaces = 0.0.0.0\n' >"$FACTS/mta_cfg"
    check 2.1.22
    assert_state 2.1.22 FAIL
}

@test "2.3.1.1: exactly one time daemon, not two and not none" {
    fx hardened
    check 2.3.1.1
    assert_state 2.3.1.1 PASS
    printf 'systemd-timesyncd.service\tenabled\tenabled\n' >>"$FACTS/unit_files"
    check 2.3.1.1
    assert_state 2.3.1.1 FAIL
    sed -i '/^chrony.service/d' "$FACTS/unit_files" "$FACTS/units_all"
    sed -i '/^systemd-timesyncd.service/d' "$FACTS/unit_files"
    check 2.3.1.1
    assert_state 2.3.1.1 FAIL
}

@test "2.3.3.1: chrony needs a server or pool line, also in sourcedir files" {
    fx hardened
    check 2.3.3.1
    assert_state 2.3.3.1 PASS
    sed -i '/^pool/d' "$RFS/etc/chrony/chrony.conf"
    check 2.3.3.1
    assert_state 2.3.3.1 FAIL
    printf 'server time.example.org iburst\n' >"$RFS/etc/chrony/sources.d/site.sources"
    check 2.3.3.1
    assert_state 2.3.3.1 PASS
}

@test "2.3.3.2: chronyd must run as _chrony" {
    fx hardened
    check 2.3.3.2
    assert_state 2.3.3.2 PASS
    sed -i 's/^_chrony /root    /' "$FACTS/ps_chronyd"
    check 2.3.3.2
    assert_state 2.3.3.2 FAIL
}

@test "2.4.1.9 / 2.4.2.1: allow files must exist with the right mode" {
    fx hardened
    check 2.4.1.9
    assert_state 2.4.1.9 PASS
    sset /etc/cron.allow - - -
    check 2.4.1.9
    assert_state 2.4.1.9 FAIL
    sset /etc/cron.allow 640 root crontab
    sset /etc/cron.deny 644 root root
    printf 'x\n' >"$RFS/etc/cron.deny"
    check 2.4.1.9
    assert_state 2.4.1.9 FAIL
}

@test "2.4.2.1: at rules apply only when at is installed" {
    fx hardened
    check 2.4.2.1
    assert_state 2.4.2.1 N/A
    printf 'at\tinstalled\t3\n' >>"$FACTS/dpkg"
    check 2.4.2.1
    assert_state 2.4.2.1 FAIL
}

# ---- section 3 / 4 --------------------------------------------------------------------
@test "3.1.2: a wireless interface needs its driver blocked" {
    fx hardened
    check 3.1.2
    assert_state 3.1.2 PASS
    printf 'iwlwifi\n' >"$FACTS/wireless_modules"
    check 3.1.2
    assert_state 3.1.2 FAIL
    printf 'blacklist iwlwifi\ninstall iwlwifi /bin/false\n' >>"$FACTS/modprobe_cfg"
    check 3.1.2
    assert_state 3.1.2 PASS
}

@test "4.1.2: ufw must be enabled, active and report Status: active" {
    fx hardened
    check 4.1.2
    assert_state 4.1.2 PASS
    printf 'Status: inactive\n' >"$FACTS/ufw_status"
    check 4.1.2
    assert_state 4.1.2 FAIL
}

@test "4.1.3: incoming default must be deny or reject" {
    fx hardened
    check 4.1.3
    assert_state 4.1.3 PASS
    sed -i 's/deny (incoming)/allow (incoming)/' "$FACTS/ufw_status"
    check 4.1.3
    assert_state 4.1.3 FAIL
    sed -i 's/allow (incoming)/reject (incoming)/' "$FACTS/ufw_status"
    check 4.1.3
    assert_state 4.1.3 PASS
}

@test "4.1.5: routed default is deny, or disabled with DEFAULT_FORWARD_POLICY=DROP" {
    fx hardened
    check 4.1.5
    assert_state 4.1.5 PASS
    sed -i 's/DROP/ACCEPT/' "$RFS/etc/default/ufw"
    check 4.1.5
    assert_state 4.1.5 FAIL
    sed -i 's/disabled (routed)/deny (routed)/' "$FACTS/ufw_status"
    check 4.1.5
    assert_state 4.1.5 PASS
    sed -i 's/deny (routed)/allow (routed)/' "$FACTS/ufw_status"
    check 4.1.5
    assert_state 4.1.5 FAIL
}

# ---- section 5 -------------------------------------------------------------------------
@test "5.2.2: use_pty must be set explicitly and never negated" {
    fx hardened
    check 5.2.2
    assert_state 5.2.2 PASS
    sed -i '/use_pty/d' "$RFS/etc/sudoers"
    check 5.2.2
    assert_state 5.2.2 FAIL
    printf 'Defaults use_pty\n' >"$RFS/etc/sudoers.d/10-pty"
    check 5.2.2
    assert_state 5.2.2 PASS
    printf 'Defaults !use_pty\n' >"$RFS/etc/sudoers.d/99-nopty"
    check 5.2.2
    assert_state 5.2.2 FAIL
}

@test "5.2.2: files named in #includedir are honoured, files with a dot are not read" {
    fx hardened
    sed -i '/use_pty/d' "$RFS/etc/sudoers"
    printf 'Defaults use_pty\n' >"$RFS/etc/sudoers.d/10-pty.disabled"
    check 5.2.2
    assert_state 5.2.2 FAIL
}

@test "5.2.3: sudo logging evidence from the journal, or logfile= on classic sudo" {
    fx hardened
    check 5.2.3
    assert_state 5.2.3 PASS
    : >"$FACTS/sudo_log"
    check 5.2.3
    assert_state 5.2.3 FAIL
    sed -i '/^sudo-rs\t/d' "$FACTS/dpkg"
    printf 'sudo\tinstalled\t1.9\n' >>"$FACTS/dpkg"
    printf 'Defaults logfile="/var/log/sudo.log"\n' >>"$RFS/etc/sudoers"
    check 5.2.3
    assert_state 5.2.3 PASS
}

@test "5.2.5: !authenticate anywhere in sudoers fails" {
    fx hardened
    check 5.2.5
    assert_state 5.2.5 PASS
    printf 'deploy ALL=(ALL) NOPASSWD: !authenticate ALL\n' >"$RFS/etc/sudoers.d/50-x"
    check 5.2.5
    assert_state 5.2.5 FAIL
}

@test "5.2.6: timestamp_timeout must be explicit, not negative and at most 15" {
    fx hardened
    check 5.2.6
    assert_state 5.2.6 PASS
    sed -i 's/timestamp_timeout=15/timestamp_timeout=20/' "$RFS/etc/sudoers"
    check 5.2.6
    assert_state 5.2.6 FAIL
    sed -i 's/timestamp_timeout=20/timestamp_timeout=-1/' "$RFS/etc/sudoers"
    check 5.2.6
    assert_state 5.2.6 FAIL
    sed -i 's/, timestamp_timeout=-1//' "$RFS/etc/sudoers"
    check 5.2.6
    assert_state 5.2.6 FAIL
}

@test "5.2.7: su is restricted with pam_wheel and an empty group" {
    fx hardened
    check 5.2.7
    assert_state 5.2.7 PASS
    sed -i 's/^sugroup:x:2000:/sugroup:x:2000:deploy/' "$RFS/etc/group"
    check 5.2.7
    assert_state 5.2.7 FAIL
    sed -i '/pam_wheel/d' "$RFS/etc/pam.d/su"
    check 5.2.7
    assert_state 5.2.7 FAIL
}

@test "5.4.1.1 / 5.4.1.3 / 5.4.1.5: login.defs and per-user shadow fields" {
    fx hardened
    audit --only 5.4.1.1,5.4.1.3,5.4.1.4,5.4.1.5,5.4.1.6
    assert_state 5.4.1.1 PASS
    assert_state 5.4.1.3 PASS
    assert_state 5.4.1.4 PASS
    assert_state 5.4.1.5 PASS
    assert_state 5.4.1.6 PASS
    sed -i 's/:20000:1:365:7:30::/:20000:1:99999:3:90::/' "$RFS/etc/shadow"
    audit --only 5.4.1.1,5.4.1.3,5.4.1.5
    assert_state 5.4.1.1 FAIL
    assert_state 5.4.1.3 FAIL
    assert_state 5.4.1.5 FAIL
}

@test "5.4.1.4: only SHA512 or YESCRYPT" {
    fx hardened
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD MD5/' "$RFS/etc/login.defs"
    check 5.4.1.4
    assert_state 5.4.1.4 FAIL
}

@test "5.4.1.6: a password change date in the future fails" {
    fx hardened
    sed -i 's/:20000:1:365:7:30::/:99999:1:365:7:30::/' "$RFS/etc/shadow"
    check 5.4.1.6
    assert_state 5.4.1.6 FAIL
}

@test "5.4.2.1 - 5.4.2.4: root is the only UID 0 / GID 0 account, root is locked or has a password" {
    fx hardened
    audit --only 5.4.2.1,5.4.2.2,5.4.2.3,5.4.2.4
    assert_state 5.4.2.1 PASS
    assert_state 5.4.2.2 PASS
    assert_state 5.4.2.3 PASS
    assert_state 5.4.2.4 PASS
    printf 'toor:x:0:0::/root:/bin/bash\n' >>"$RFS/etc/passwd"
    printf 'wheel0:x:0:\n' >>"$RFS/etc/group"
    sed -i 's/^root:\*:/root::/' "$RFS/etc/shadow"
    audit --only 5.4.2.1,5.4.2.2,5.4.2.3,5.4.2.4
    assert_state 5.4.2.1 FAIL
    assert_state 5.4.2.2 FAIL
    assert_state 5.4.2.3 FAIL
    assert_state 5.4.2.4 FAIL
}

@test "5.4.2.5: root PATH must not contain ., empty entries or writable directories" {
    fx hardened
    check 5.4.2.5
    assert_state 5.4.2.5 PASS
    printf '/usr/bin::/bin:.\n' >"$FACTS/root_path"
    check 5.4.2.5
    assert_state 5.4.2.5 FAIL
    printf '/usr/local/bin:/usr/bin\n' >"$FACTS/root_path"
    sset /usr/local/bin 775 root root d
    check 5.4.2.5
    assert_state 5.4.2.5 FAIL
}

@test "5.4.2.6: a root umask looser than 027 fails" {
    fx hardened
    check 5.4.2.6
    assert_state 5.4.2.6 PASS
    printf 'umask 022\n' >"$RFS/root/.bashrc"
    check 5.4.2.6
    assert_state 5.4.2.6 FAIL
}

@test "5.4.2.7 / 5.4.2.8: system accounts without valid shells, locked" {
    fx hardened
    audit --only 5.4.2.7,5.4.2.8
    assert_state 5.4.2.7 PASS
    assert_state 5.4.2.8 PASS
    sed -i 's|^daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin|daemon:x:1:1:daemon:/usr/sbin:/bin/bash|' "$RFS/etc/passwd"
    sed -i 's/^bin:\*:/bin:$6$x$y:/' "$RFS/etc/shadow"
    audit --only 5.4.2.7,5.4.2.8
    assert_state 5.4.2.7 FAIL
    assert_state 5.4.2.8 FAIL
}

@test "5.4.3.2: TMOUT readonly, exported and at most 900" {
    fx hardened
    check 5.4.3.2
    assert_state 5.4.3.2 PASS
    printf 'TMOUT=900\nexport TMOUT\n' >"$RFS/etc/profile.d/60-cis-tmout.sh"
    check 5.4.3.2
    assert_state 5.4.3.2 FAIL
    printf 'readonly TMOUT=1800\nexport TMOUT\n' >"$RFS/etc/profile.d/60-cis-tmout.sh"
    check 5.4.3.2
    assert_state 5.4.3.2 FAIL
    rm "$RFS/etc/profile.d/60-cis-tmout.sh"
    check 5.4.3.2
    assert_state 5.4.3.2 FAIL
}

@test "5.4.3.2: TMOUT_MAX from site.conf tightens the limit" {
    fx hardened
    printf 'TMOUT_MAX=600\n' >"$FX/site.conf"
    check 5.4.3.2 --config "$FX/site.conf"
    assert_state 5.4.3.2 FAIL
}

@test "5.4.3.3: umask must be 027 or stricter, whatever the spacing" {
    fx hardened
    check 5.4.3.3
    assert_state 5.4.3.3 PASS
    printf 'UMASK           022\n' >"$RFS/etc/login.defs"
    check 5.4.3.3
    assert_state 5.4.3.3 FAIL
    printf 'UMASK           027\n' >"$RFS/etc/login.defs"
    printf 'umask    027\n' >"$RFS/etc/profile"
    check 5.4.3.3
    assert_state 5.4.3.3 PASS
    printf 'umask 002\n' >"$RFS/etc/profile.d/99-loose.sh"
    check 5.4.3.3
    assert_state 5.4.3.3 FAIL
}

# ---- section 6 -------------------------------------------------------------------------
@test "6.1.2.3: FileCreateMode must be 0640 or stricter (rsyslog hosts)" {
    fx hardened
    printf 'LOGGER=rsyslog\n' >"$FX/site.conf"
    printf '$FileCreateMode 0644\n' >"$RFS/etc/rsyslog.conf"
    check 6.1.2.3 --config "$FX/site.conf"
    assert_state 6.1.2.3 FAIL
    printf '$FileCreateMode 0640\n' >"$RFS/etc/rsyslog.conf"
    check 6.1.2.3 --config "$FX/site.conf"
    assert_state 6.1.2.3 PASS
    printf '# nothing\n' >"$RFS/etc/rsyslog.conf"
    check 6.1.2.3 --config "$FX/site.conf"
    assert_state 6.1.2.3 FAIL
}

@test "6.1.2.6: rsyslog must not receive remote logs" {
    fx hardened
    printf 'LOGGER=rsyslog\n' >"$FX/site.conf"
    printf '# module(load="imudp")\n' >"$RFS/etc/rsyslog.conf"
    check 6.1.2.6 --config "$FX/site.conf"
    assert_state 6.1.2.6 PASS
    printf 'module(load="imtcp")\ninput(type="imtcp" port="514")\n' >"$RFS/etc/rsyslog.conf"
    check 6.1.2.6 --config "$FX/site.conf"
    assert_state 6.1.2.6 FAIL
    printf '$ModLoad imudp\n' >"$RFS/etc/rsyslog.conf"
    check 6.1.2.6 --config "$FX/site.conf"
    assert_state 6.1.2.6 FAIL
}

@test "6.1.3.1: log files are judged by name (PDF script port)" {
    fx hardened
    check 6.1.3.1
    assert_state 6.1.3.1 PASS
    printf '644\troot\troot\t/var/log/syslog\n' >"$FACTS/logfiles"
    check 6.1.3.1
    assert_state 6.1.3.1 FAIL
    printf '664\troot\tutmp\t/var/log/wtmp\n' >"$FACTS/logfiles"
    check 6.1.3.1
    assert_state 6.1.3.1 PASS
    printf '664\troot\tutmp\t/var/log/btmp.1\n660\troot\tutmp\t/var/log/lastlog\n' >"$FACTS/logfiles"
    check 6.1.3.1
    assert_state 6.1.3.1 PASS
    printf '666\troot\troot\t/var/log/custom.log\n' >"$FACTS/logfiles"
    check 6.1.3.1
    assert_state 6.1.3.1 FAIL
    printf '640\tsyslog\tadm\t/var/log/apt/term.log\n' >"$FACTS/logfiles"
    check 6.1.3.1
    assert_state 6.1.3.1 FAIL
}

@test "6.1.3.1: files of a service account without a login shell may be owned by it" {
    fx hardened
    printf '640\t_chrony\t_chrony\t/var/log/chrony/tracking.log\n' >"$FACTS/logfiles"
    check 6.1.3.1
    assert_state 6.1.3.1 PASS
    printf '640\tdeploy\tdeploy\t/var/log/app.log\n' >"$FACTS/logfiles"
    check 6.1.3.1
    assert_state 6.1.3.1 FAIL
}

@test "6.3.2: AIDE timer enabled and active" {
    fx hardened
    check 6.3.2
    assert_state 6.3.2 PASS
    sed -i '/^dailyaidecheck.timer/d' "$FACTS/units_all"
    check 6.3.2
    assert_state 6.3.2 FAIL
    sed -i '/^dailyaidecheck.timer/d' "$FACTS/unit_files"
    check 6.3.2
    assert_state 6.3.2 FAIL
}

# ---- section 7 -------------------------------------------------------------------------
@test "7.1.11 / 7.1.12: results of the filesystem walks decide" {
    fx hardened
    audit --only 7.1.11,7.1.12
    assert_state 7.1.11 PASS
    assert_state 7.1.12 PASS
    printf 'f\t/srv/x\nd\t/srv/shared\n' >"$FACTS/fs_world"
    printf 'g\t/opt/orphan\n' >"$FACTS/fs_nouser"
    audit --only 7.1.11,7.1.12
    assert_state 7.1.11 FAIL
    assert_state 7.1.12 FAIL
}

@test "7.1.11: ERROR when the walk fact is missing (timeout)" {
    fx hardened
    rm "$FACTS/fs_world"
    check 7.1.11
    assert_state 7.1.11 ERROR
}

@test "7.1.13: SUID/SGID files are listed as MANUAL evidence" {
    fx hardened
    check 7.1.13
    assert_state 7.1.13 MANUAL
    [[ "$(evidence_of 7.1.13)" == *"/usr/bin/sudo"* ]]
}

@test "7.2.1 / 7.2.2: shadowed passwords and non-empty shadow fields" {
    fx hardened
    audit --only 7.2.1,7.2.2
    assert_state 7.2.1 PASS
    assert_state 7.2.2 PASS
    sed -i 's/^deploy:x:/deploy:$6$x:/' "$RFS/etc/passwd"
    sed -i 's/^nobody:\*:/nobody::/' "$RFS/etc/shadow"
    audit --only 7.2.1,7.2.2
    assert_state 7.2.1 FAIL
    assert_state 7.2.2 FAIL
}

@test "7.2.3 / 7.2.4: dangling GIDs and the shadow group" {
    fx hardened
    audit --only 7.2.3,7.2.4
    assert_state 7.2.3 PASS
    assert_state 7.2.4 PASS
    printf 'orphan:x:3000:3000::/home/orphan:/bin/bash\n' >>"$RFS/etc/passwd"
    sed -i 's/^shadow:x:42:/shadow:x:42:deploy/' "$RFS/etc/group"
    audit --only 7.2.3,7.2.4
    assert_state 7.2.3 FAIL
    assert_state 7.2.4 FAIL
}

@test "7.2.5 - 7.2.8: duplicate UIDs, GIDs and names" {
    fx hardened
    audit --only 7.2.5,7.2.6,7.2.7,7.2.8
    assert_state 7.2.5 PASS
    assert_state 7.2.6 PASS
    assert_state 7.2.7 PASS
    assert_state 7.2.8 PASS
    printf 'deploy:x:1001:1000::/home/d2:/bin/bash\ntwin:x:1000:1000::/home/t:/bin/bash\n' >>"$RFS/etc/passwd"
    printf 'deploy:x:1005:\nother:x:1000:\n' >>"$RFS/etc/group"
    audit --only 7.2.5,7.2.6,7.2.7,7.2.8
    assert_state 7.2.5 FAIL
    assert_state 7.2.6 FAIL
    assert_state 7.2.7 FAIL
    assert_state 7.2.8 FAIL
}

@test "7.2.9: home directory must exist, belong to the user and be 0750 or stricter" {
    fx hardened
    check 7.2.9
    assert_state 7.2.9 PASS
    sset /home/deploy 755 deploy deploy d
    check 7.2.9
    assert_state 7.2.9 FAIL
    sset /home/deploy 750 root deploy d
    check 7.2.9
    assert_state 7.2.9 FAIL
    sset /home/deploy - - -
    check 7.2.9
    assert_state 7.2.9 FAIL
}

@test "7.2.10: dot files (.forward, .netrc, .bash_history, others)" {
    fx hardened
    check 7.2.10
    assert_state 7.2.10 PASS
    printf 'f\tdeploy\t644\tdeploy\tdeploy\t/home/deploy/.forward\n' >>"$FACTS/home_dots"
    check 7.2.10
    assert_state 7.2.10 FAIL
}

@test "7.2.10: .bash_history must be 0600 and group-owned by the primary group" {
    fx hardened
    sed -i 's|^f\tdeploy\t600\tdeploy\tdeploy\t/home/deploy/.bash_history|f\tdeploy\t644\tdeploy\tdeploy\t/home/deploy/.bash_history|' "$FACTS/home_dots"
    check 7.2.10
    assert_state 7.2.10 FAIL
    sed -i 's|^f\tdeploy\t644\tdeploy\tdeploy\t/home/deploy/.bash_history|f\tdeploy\t600\tdeploy\tstaff\t/home/deploy/.bash_history|' "$FACTS/home_dots"
    check 7.2.10
    assert_state 7.2.10 FAIL
}

@test "7.2.10 / 7.2.11: homes on network filesystems are skipped" {
    fx hardened
    sed -i 's|^home\tdeploy\t/home/deploy\text4|home\tdeploy\t/home/deploy\tnfs4|' "$FACTS/home_dots"
    printf 'f\tdeploy\t666\tdeploy\tdeploy\t/home/deploy/.bashrc\n' >>"$FACTS/home_dots"
    audit --only 7.2.10,7.2.11
    assert_state 7.2.10 PASS
    assert_state 7.2.11 PASS
}

@test "7.2.11: dot directories 0750 or stricter, .ssh 0700" {
    fx hardened
    check 7.2.11
    assert_state 7.2.11 PASS
    sed -i 's|^d\tdeploy\t700\tdeploy\tdeploy\t/home/deploy/.ssh|d\tdeploy\t750\tdeploy\tdeploy\t/home/deploy/.ssh|' "$FACTS/home_dots"
    check 7.2.11
    assert_state 7.2.11 FAIL
}
