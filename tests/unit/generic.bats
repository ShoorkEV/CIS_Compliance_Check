#!/usr/bin/env bats
# One PASS, one FAIL and one N/A or ERROR case for each generic check type.
# Every test starts from the "hardened" fixture and breaks exactly one thing.

load helpers

# ---- sysctl -------------------------------------------------------------------
@test "sysctl: PASS when running and persisted values match" {
    fx hardened
    check 3.3.1.1
    assert_state 3.3.1.1 PASS
}

@test "sysctl: FAIL when only the running value is wrong" {
    fx hardened
    sed -i 's/^net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/' "$FACTS/sysctl_running"
    check 3.3.1.1
    assert_state 3.3.1.1 FAIL
    [[ "$(evidence_of 3.3.1.1)" == *"running=1"* ]]
}

@test "sysctl: FAIL when the value is not persisted" {
    fx hardened
    sed -i '/^net.ipv4.ip_forward = 0/d' "$FACTS/sysctl_cat"
    check 3.3.1.1
    assert_state 3.3.1.1 FAIL
    [[ "$(evidence_of 3.3.1.1)" == *"persisted=not set"* ]]
}

@test "sysctl: the last assignment in load order wins" {
    fx hardened
    printf '# /etc/sysctl.d/99-late.conf\nnet.ipv4.ip_forward = 1\n' >>"$FACTS/sysctl_cat"
    check 3.3.1.1
    assert_state 3.3.1.1 FAIL
}

@test "sysctl: the ufw sysctl file wins when ufw is enabled" {
    fx hardened
    printf 'net/ipv4/ip_forward=1\n' >"$RFS/etc/ufw/sysctl.conf"
    check 3.3.1.1
    assert_state 3.3.1.1 FAIL
    sed -i 's/^ENABLED=.*/ENABLED=no/' "$RFS/etc/ufw/ufw.conf"
    check 3.3.1.1
    assert_state 3.3.1.1 PASS
}

@test "sysctl: several accepted values (1.5.3 accepts 1, 2 or 3)" {
    fx hardened
    sed -i 's/^kernel.yama.ptrace_scope = .*/kernel.yama.ptrace_scope = 0/' "$FACTS/sysctl_running" "$FACTS/sysctl_cat"
    check 1.5.3
    assert_state 1.5.3 FAIL
    sed -i 's/^kernel.yama.ptrace_scope = .*/kernel.yama.ptrace_scope = 3/' "$FACTS/sysctl_running" "$FACTS/sysctl_cat"
    check 1.5.3
    assert_state 1.5.3 PASS
}

@test "sysctl: IPv6 rules are N/A when IPv6 is disabled" {
    fx hardened
    echo 1 >"$RFS/sys/module/ipv6/parameters/disable"
    check 3.3.2.1
    assert_state 3.3.2.1 N/A
}

@test "sysctl: ERROR when the running sysctl fact is unavailable" {
    fx hardened
    rm "$FACTS/sysctl_running"
    check 3.3.1.1
    assert_state 3.3.1.1 ERROR
}

# ---- file_perm ------------------------------------------------------------------
@test "file_perm: PASS for the benchmark mode, owner and group" {
    fx hardened
    check 7.1.5
    assert_state 7.1.5 PASS
}

@test "file_perm: FAIL when the mode is too open" {
    fx hardened
    sset /etc/shadow 644 root shadow
    check 7.1.5
    assert_state 7.1.5 FAIL
    [[ "$(evidence_of 7.1.5)" == *"mode 0644 grants 0004"* ]]
}

@test "file_perm: FAIL on a wrong group, PASS on an allowed alternative" {
    fx hardened
    sset /etc/shadow 640 root staff
    check 7.1.5
    assert_state 7.1.5 FAIL
    sset /etc/shadow 600 root root
    check 7.1.5
    assert_state 7.1.5 PASS
}

@test "file_perm: a missing optional file passes, a required one fails" {
    fx hardened
    sset /etc/gshadow- - - -
    sset /etc/gshadow - - -
    audit --only 7.1.7,7.1.8
    assert_state 7.1.8 PASS
    assert_state 7.1.7 FAIL
}

@test "file_perm: several paths, all must comply (5.1.1 sshd_config and drop-ins)" {
    fx hardened
    sset /etc/ssh/sshd_config.d/60-cis.conf 644 root root
    check 5.1.1
    assert_state 5.1.1 FAIL
}

@test "file_perm: a mode with setuid bits is not allowed by a plain maximum" {
    fx hardened
    sset /etc/passwd 4644 root root
    check 7.1.1
    assert_state 7.1.1 FAIL
}

# ---- file_perm_glob ---------------------------------------------------------------
@test "file_perm_glob: PASS and FAIL on files below a directory" {
    fx hardened
    check 1.2.1.9
    assert_state 1.2.1.9 PASS
    printf 'x\n' >"$RFS/etc/apt/sources.list.d/extra.list"
    sset /etc/apt/sources.list.d/extra.list 664 root root
    check 1.2.1.9
    assert_state 1.2.1.9 FAIL
}

@test "file_perm_glob: an empty or missing directory passes" {
    fx hardened
    check 1.2.1.6
    assert_state 1.2.1.6 PASS
}

@test "file_perm_glob: SSH host keys come from sshd -T (5.1.3 private, 5.1.4 public)" {
    fx hardened
    audit --only 5.1.3,5.1.4
    assert_state 5.1.3 PASS
    assert_state 5.1.4 PASS
    sset /etc/ssh/ssh_host_ed25519_key 640 root root
    audit --only 5.1.3,5.1.4
    assert_state 5.1.3 FAIL
}

# ---- svc_not_in_use ------------------------------------------------------------------
@test "svc_not_in_use: PASS when the package is not installed" {
    fx hardened
    check 2.1.1
    assert_state 2.1.1 PASS
}

@test "svc_not_in_use: FAIL when installed and the unit is enabled" {
    fx hardened
    printf 'autofs\tinstalled\t5.1\n' >>"$FACTS/dpkg"
    printf 'autofs.service\tenabled\tenabled\n' >>"$FACTS/unit_files"
    check 2.1.1
    assert_state 2.1.1 FAIL
}

@test "svc_not_in_use: FAIL when installed and the unit is only active" {
    fx hardened
    printf 'autofs\tinstalled\t5.1\n' >>"$FACTS/dpkg"
    printf 'autofs.service\tdisabled\tenabled\n' >>"$FACTS/unit_files"
    printf 'autofs.service loaded active running Automounter\n' >>"$FACTS/units_all"
    check 2.1.1
    assert_state 2.1.1 FAIL
}

@test "svc_not_in_use: PASS when installed for a dependency but disabled and inactive" {
    fx hardened
    printf 'autofs\tinstalled\t5.1\n' >>"$FACTS/dpkg"
    printf 'autofs.service\tdisabled\tenabled\n' >>"$FACTS/unit_files"
    check 2.1.1
    assert_state 2.1.1 PASS
}

@test "svc_not_in_use: a rule without packages looks at the unit only (1.6.12)" {
    fx hardened
    check 1.6.12
    assert_state 1.6.12 PASS
    sed -i 's/^update-notifier-motd.timer\tdisabled/update-notifier-motd.timer\tenabled/' "$FACTS/unit_files"
    check 1.6.12
    assert_state 1.6.12 FAIL
}

# ---- sshd_param -------------------------------------------------------------------
@test "sshd_param: PASS and FAIL for a simple value (5.1.22)" {
    fx hardened
    check 5.1.22
    assert_state 5.1.22 PASS
    sed -i 's/^permitrootlogin .*/permitrootlogin yes/' "$FACTS/sshd_T"
    check 5.1.22
    assert_state 5.1.22 FAIL
}

@test "sshd_param: a Match block that weakens the setting is found" {
    fx hardened
    printf 'Match User batch\n    PermitRootLogin yes\n' >>"$RFS/etc/ssh/sshd_config"
    sed 's/^permitrootlogin .*/permitrootlogin yes/' "$FACTS/sshd_T" >"$FACTS/sshd_T_C"
    check 5.1.22
    assert_state 5.1.22 FAIL
    [[ "$(evidence_of 5.1.22)" == *"Match evaluated"* ]]
}

@test "sshd_param: numeric limits (5.1.18 MaxAuthTries <= 4)" {
    fx hardened
    sed -i 's/^maxauthtries .*/maxauthtries 6/' "$FACTS/sshd_T"
    check 5.1.18
    assert_state 5.1.18 FAIL
}

@test "sshd_param: LoginGraceTime must be between 1 and 60" {
    fx hardened
    for v in 0 61; do
        sed -i "s/^logingracetime .*/logingracetime $v/" "$FACTS/sshd_T"
        check 5.1.15
        assert_state 5.1.15 FAIL
    done
    sed -i 's/^logingracetime .*/logingracetime 60/' "$FACTS/sshd_T"
    check 5.1.15
    assert_state 5.1.15 PASS
}

@test "sshd_param: weak algorithms in comma lists (ciphers, MACs, KEX)" {
    fx hardened
    sed -i 's/^ciphers .*/ciphers aes256-gcm@openssh.com,aes128-cbc/' "$FACTS/sshd_T"
    sed -i 's/^macs .*/macs hmac-sha2-256-etm@openssh.com,umac-64@openssh.com/' "$FACTS/sshd_T"
    sed -i 's/^kexalgorithms .*/kexalgorithms mlkem768x25519-sha256,diffie-hellman-group14-sha1/' "$FACTS/sshd_T"
    audit --only 5.1.7,5.1.13,5.1.17
    assert_state 5.1.7 FAIL
    assert_state 5.1.13 FAIL
    assert_state 5.1.17 FAIL
}

@test "sshd_param: OpenSSH 10 ML-KEM names are parsed (5.1.13 passes)" {
    fx hardened
    check 5.1.13
    assert_state 5.1.13 PASS
}

@test "sshd_param: MaxStartups compares all three numbers" {
    fx hardened
    sed -i 's/^maxstartups .*/maxstartups 10:30:100/' "$FACTS/sshd_T"
    check 5.1.20
    assert_state 5.1.20 FAIL
    sed -i 's/^maxstartups .*/maxstartups 5:20:40/' "$FACTS/sshd_T"
    check 5.1.20
    assert_state 5.1.20 PASS
}

@test "sshd_param: ClientAlive settings must both be above zero (5.1.8)" {
    fx hardened
    sed -i 's/^clientalivecountmax .*/clientalivecountmax 0/' "$FACTS/sshd_T"
    check 5.1.8
    assert_state 5.1.8 FAIL
}

@test "sshd_param: one of the Allow/Deny directives must be set (5.1.5)" {
    fx hardened
    sed -i '/^allowusers /d' "$FACTS/sshd_T"
    check 5.1.5
    assert_state 5.1.5 FAIL
}

@test "sshd_param: banner must be a file without OS information (1.6.5 and 5.1.6)" {
    fx hardened
    audit --only 1.6.5,5.1.6
    assert_state 1.6.5 PASS
    assert_state 5.1.6 PASS
    printf 'Ubuntu 26.04 LTS\n' >"$RFS/etc/issue.net"
    audit --only 1.6.5,5.1.6
    assert_state 1.6.5 FAIL
    assert_state 5.1.6 FAIL
}

@test "sshd_param: MaxSessions is also checked in the config files (5.1.19)" {
    fx hardened
    printf 'MaxSessions 50\n' >"$RFS/etc/ssh/sshd_config.d/70-late.conf"
    check 5.1.19
    assert_state 5.1.19 FAIL
}

@test "sshd_param: ERROR when sshd -T is unavailable" {
    fx hardened
    rm "$FACTS/sshd_T"
    check 5.1.22
    assert_state 5.1.22 ERROR
}

# ---- mount_opt / mount_tmpfs_or_separate ---------------------------------------------
@test "mount_opt: PASS, FAIL and N/A when the path is not a separate mount" {
    fx hardened
    check 1.1.2.3.2
    assert_state 1.1.2.3.2 PASS
    sed -i 's|\(TARGET="/home".*OPTIONS="\)rw,nosuid,nodev,relatime|\1rw,nosuid,relatime|' "$FACTS/mounts"
    check 1.1.2.3.2
    assert_state 1.1.2.3.2 FAIL
    sed -i '/TARGET="\/home"/d' "$FACTS/mounts"
    check 1.1.2.3.2
    assert_state 1.1.2.3.2 N/A
}

@test "mount_tmpfs_or_separate: FAIL without a /tmp mount, FAIL when tmp.mount is masked" {
    fx hardened
    check 1.1.2.1.1
    assert_state 1.1.2.1.1 PASS
    sed -i 's/^tmp.mount\tgenerated/tmp.mount\tmasked/' "$FACTS/unit_files"
    check 1.1.2.1.1
    assert_state 1.1.2.1.1 FAIL
    sed -i '/TARGET="\/tmp"/d' "$FACTS/mounts"
    check 1.1.2.1.1
    assert_state 1.1.2.1.1 FAIL
}

# ---- conf_kv --------------------------------------------------------------------------
@test "conf_kv: pwquality value must meet the minimum (5.3.3.2.2)" {
    fx hardened
    check 5.3.3.2.2
    assert_state 5.3.3.2.2 PASS
    sed -i 's/^minlen = .*/minlen = 12/' "$RFS/etc/security/pwquality.conf.d/50-cis.conf"
    check 5.3.3.2.2
    assert_state 5.3.3.2.2 FAIL
}

@test "conf_kv: the main pwquality.conf overrides the drop-in directory" {
    fx hardened
    printf 'minlen = 8\n' >"$RFS/etc/security/pwquality.conf"
    check 5.3.3.2.2
    assert_state 5.3.3.2.2 FAIL
}

@test "conf_kv: a module argument on the PAM line overrides the file" {
    fx hardened
    sed -i 's/pam_pwquality.so retry=3/pam_pwquality.so retry=3 minlen=8/' "$RFS/etc/pam.d/common-password"
    check 5.3.3.2.2
    assert_state 5.3.3.2.2 FAIL
}

@test "conf_kv: a missing required setting fails, a missing optional one passes" {
    fx hardened
    sed -i '/^minlen/d;/^dictcheck/d' "$RFS/etc/security/pwquality.conf.d/50-cis.conf"
    audit --only 5.3.3.2.2,5.3.3.2.6
    assert_state 5.3.3.2.2 FAIL
    assert_state 5.3.3.2.6 PASS
    printf 'dictcheck = 0\n' >>"$RFS/etc/security/pwquality.conf.d/50-cis.conf"
    check 5.3.3.2.6
    assert_state 5.3.3.2.6 FAIL
}

@test "conf_kv: faillock deny and unlock_time (5.3.3.1.1, 5.3.3.1.2)" {
    fx hardened
    audit --only 5.3.3.1.1,5.3.3.1.2
    assert_state 5.3.3.1.1 PASS
    assert_state 5.3.3.1.2 PASS
    sed -i 's/^deny = .*/deny = 6/;s/^unlock_time = .*/unlock_time = 600/' "$RFS/etc/security/faillock.conf"
    audit --only 5.3.3.1.1,5.3.3.1.2
    assert_state 5.3.3.1.1 FAIL
    assert_state 5.3.3.1.2 FAIL
}

@test "conf_kv: unlock_time 0 (never) is accepted" {
    fx hardened
    sed -i 's/^unlock_time = .*/unlock_time = 0/' "$RFS/etc/security/faillock.conf"
    check 5.3.3.1.2
    assert_state 5.3.3.1.2 PASS
}

@test "conf_kv: enforce_for_root is a flag that must be present (5.3.3.2.8)" {
    fx hardened
    check 5.3.3.2.8
    assert_state 5.3.3.2.8 PASS
    sed -i '/^enforce_for_root/d' "$RFS/etc/security/pwquality.conf.d/50-cis.conf"
    check 5.3.3.2.8
    assert_state 5.3.3.2.8 FAIL
}

@test "conf_kv: systemd settings come from cat-config, defaults count when unset (6.1.1.1.6)" {
    fx hardened
    check 6.1.1.1.6
    assert_state 6.1.1.1.6 PASS
    sed -i '/^Storage=persistent/d' "$FACTS/catcfg.systemd_journald.conf"
    check 6.1.1.1.6
    assert_state 6.1.1.1.6 FAIL
    sed -i 's/^#Compress=yes/#Compress=no/;/^Compress=yes/d' "$FACTS/catcfg.systemd_journald.conf"
    check 6.1.1.1.7
    assert_state 6.1.1.1.7 FAIL
}

@test "conf_kv: systemd-coredump rules are N/A when the package is absent (1.5.11)" {
    fx hardened
    check 1.5.11
    assert_state 1.5.11 PASS
    sed -i '/^systemd-coredump/d' "$FACTS/dpkg"
    check 1.5.11
    assert_state 1.5.11 N/A
}

@test "conf_kv: coredump default is used when nothing is configured and fails (1.5.12)" {
    fx hardened
    sed -i '/^Storage=none/d' "$FACTS/catcfg.systemd_coredump.conf"
    check 1.5.12
    assert_state 1.5.12 FAIL
}

@test "conf_kv: timesyncd needs NTP or FallbackNTP (2.3.2.1)" {
    fx hardened
    printf 'TIME_DAEMON=timesyncd\n' >"$FX/site.conf"
    check 2.3.2.1 --config "$FX/site.conf"
    assert_state 2.3.2.1 FAIL
    printf '\n# /etc/systemd/timesyncd.conf.d/60-cis.conf\n[Time]\nNTP=ntp.example.org\n' >>"$FACTS/catcfg.systemd_timesyncd.conf"
    check 2.3.2.1 --config "$FX/site.conf"
    assert_state 2.3.2.1 PASS
}

@test "conf_kv: journald forwarding applies only with rsyslog and needs both services (6.1.1.1.3)" {
    fx hardened
    check 6.1.1.1.3
    assert_state 6.1.1.1.3 N/A
    printf 'LOGGER=rsyslog\n' >"$FX/site.conf"
    check 6.1.1.1.3 --config "$FX/site.conf"
    assert_state 6.1.1.1.3 FAIL
}

# ---- kmod_unavailable --------------------------------------------------------------------
@test "kmod_unavailable: PASS when blacklisted and not loadable" {
    fx hardened
    check 1.1.1.1
    assert_state 1.1.1.1 PASS
}

@test "kmod_unavailable: FAIL when the blacklist or the install override is missing" {
    fx hardened
    sed -i '/^blacklist cramfs/d' "$FACTS/modprobe_cfg"
    check 1.1.1.1
    assert_state 1.1.1.1 FAIL
    printf 'blacklist cramfs\n' >>"$FACTS/modprobe_cfg"
    sed -i '/^install cramfs/d' "$FACTS/modprobe_cfg"
    check 1.1.1.1
    assert_state 1.1.1.1 FAIL
}

@test "kmod_unavailable: FAIL when the module is loaded" {
    fx hardened
    printf 'cramfs 12288 0\n' >>"$FACTS/lsmod"
    check 1.1.1.1
    assert_state 1.1.1.1 FAIL
}

@test "kmod_unavailable: PASS when the module does not exist on the system" {
    fx hardened
    sed -i '/cramfs/d' "$FACTS/kmod_files" "$FACTS/modprobe_cfg"
    check 1.1.1.1
    assert_state 1.1.1.1 PASS
}

@test "kmod_unavailable: dash and underscore are the same module (usb-storage)" {
    fx hardened
    sed -i 's/usb_storage/usb-storage/' "$FACTS/modprobe_cfg"
    check 1.1.1.10
    assert_state 1.1.1.10 PASS
    printf 'usb_storage 90112 0\n' >>"$FACTS/lsmod"
    check 1.1.1.10
    assert_state 1.1.1.10 FAIL
}

@test "kmod_unavailable: install ... /bin/true is as good as /bin/false" {
    fx hardened
    sed -i 's|^install sctp /bin/false|install sctp /bin/true|' "$FACTS/modprobe_cfg"
    check 3.2.5
    assert_state 3.2.5 PASS
}

# ---- pam_module ----------------------------------------------------------------------------
@test "pam_module: pam_unix without nullok (5.3.3.4.1)" {
    fx hardened
    check 5.3.3.4.1
    assert_state 5.3.3.4.1 PASS
    sed -i 's/pam_unix.so try_first_pass/pam_unix.so nullok try_first_pass/' "$RFS/etc/pam.d/common-auth"
    check 5.3.3.4.1
    assert_state 5.3.3.4.1 FAIL
}

@test "pam_module: pam_unix must not carry remember= (5.3.3.4.2)" {
    fx hardened
    sed -i 's/yescrypt/yescrypt remember=5/' "$RFS/etc/pam.d/common-password"
    check 5.3.3.4.2
    assert_state 5.3.3.4.2 FAIL
}

@test "pam_module: strong hashing and use_authtok on the password line (5.3.3.4.3 / .4)" {
    fx hardened
    audit --only 5.3.3.4.3,5.3.3.4.4
    assert_state 5.3.3.4.3 PASS
    assert_state 5.3.3.4.4 PASS
    sed -i 's/ use_authtok//;s/ yescrypt//' "$RFS/etc/pam.d/common-password"
    audit --only 5.3.3.4.3,5.3.3.4.4
    assert_state 5.3.3.4.3 FAIL
    assert_state 5.3.3.4.4 FAIL
}

@test "pam_module: module must be present in every listed file (5.3.2.1)" {
    fx hardened
    check 5.3.2.1
    assert_state 5.3.2.1 PASS
    sed -i '/pam_unix.so/d' "$RFS/etc/pam.d/common-session"
    check 5.3.2.1
    assert_state 5.3.2.1 FAIL
}

@test "pam_module: faillock needs preauth and authfail in common-auth (5.3.2.2)" {
    fx hardened
    check 5.3.2.2
    assert_state 5.3.2.2 PASS
    sed -i '/authfail/d' "$RFS/etc/pam.d/common-auth"
    check 5.3.2.2
    assert_state 5.3.2.2 FAIL
}

@test "pam_module: pwhistory configured in the conf file only (5.3.3.3.1)" {
    fx hardened
    check 5.3.3.3.1
    assert_state 5.3.3.3.1 PASS
}

@test "pam_module: pwhistory configured on the PAM line only (5.3.3.3.1)" {
    fx hardened
    rm "$RFS/etc/security/pwhistory.conf"
    sed -i 's/pam_pwhistory.so/pam_pwhistory.so remember=24 enforce_for_root use_authtok/' "$RFS/etc/pam.d/common-password"
    audit --only 5.3.3.3.1,5.3.3.3.2,5.3.3.3.3
    assert_state 5.3.3.3.1 PASS
    assert_state 5.3.3.3.2 PASS
    assert_state 5.3.3.3.3 PASS
}

@test "pam_module: pwhistory configured in both places is a failure" {
    fx hardened
    sed -i 's/pam_pwhistory.so/pam_pwhistory.so remember=24/' "$RFS/etc/pam.d/common-password"
    check 5.3.3.3.1
    assert_state 5.3.3.3.1 FAIL
}

@test "pam_module: remember below 24 fails" {
    fx hardened
    sed -i 's/^remember = .*/remember = 10/' "$RFS/etc/security/pwhistory.conf"
    check 5.3.3.3.1
    assert_state 5.3.3.3.1 FAIL
}

# ---- packages ----------------------------------------------------------------------------------
@test "pkg_installed: PASS and FAIL (4.1.1 ufw)" {
    fx hardened
    check 4.1.1
    assert_state 4.1.1 PASS
    sed -i '/^ufw\t/d' "$FACTS/dpkg"
    check 4.1.1
    assert_state 4.1.1 FAIL
}

@test "pkg_installed: sudo or sudo-rs, or the sssd alternative (5.2.1)" {
    fx hardened
    sed -i '/^sudo-rs\t/d' "$FACTS/dpkg"
    check 5.2.1
    assert_state 5.2.1 FAIL
    printf 'sudo\tinstalled\t1.9\n' >>"$FACTS/dpkg"
    check 5.2.1
    assert_state 5.2.1 PASS
    sed -i '/^sudo\t/d' "$FACTS/dpkg"
    printf 'libsss-sudo\tinstalled\t2\nsssd\tinstalled\t2\n' >>"$FACTS/dpkg"
    check 5.2.1
    assert_state 5.2.1 PASS
}

@test "pkg_installed: 'latest version' compares with the local apt cache (5.3.1.1)" {
    fx hardened
    check 5.3.1.1
    assert_state 5.3.1.1 PASS
    sed -i '0,/Candidate: 1.7.0-3/s//Candidate: 1.7.0-4/' "$FACTS/apt_policy"
    check 5.3.1.1
    assert_state 5.3.1.1 FAIL
    [[ "$(evidence_of 5.3.1.1)" == *"upgrade available"* ]]
}

@test "pkg_installed: all listed packages are required (1.3.1.1)" {
    fx hardened
    sed -i '/^apparmor-utils\t/d' "$FACTS/dpkg"
    check 1.3.1.1
    assert_state 1.3.1.1 FAIL
}

@test "pkg_installed: rsyslog rules are N/A when journald is the logger (6.1.2.1)" {
    fx hardened
    check 6.1.2.1
    assert_state 6.1.2.1 N/A
}

@test "pkg_absent: PASS, FAIL, and config-files counts as removed (1.5.6)" {
    fx hardened
    check 1.5.6
    assert_state 1.5.6 PASS
    printf 'prelink\tinstalled\t1\n' >>"$FACTS/dpkg"
    check 1.5.6
    assert_state 1.5.6 FAIL
    sed -i 's/^prelink\tinstalled/prelink\tconfig-files/' "$FACTS/dpkg"
    check 1.5.6
    assert_state 1.5.6 PASS
}

@test "pkg_absent: any package of a family fails (2.2.4 telnet clients)" {
    fx hardened
    printf 'inetutils-telnet\tinstalled\t2\n' >>"$FACTS/dpkg"
    check 2.2.4
    assert_state 2.2.4 FAIL
}

# ---- gdm / manual --------------------------------------------------------------------------------
@test "gdm: N/A without gdm3, MANUAL with a hint when gdm3 is installed" {
    fx hardened
    check 1.7.1
    assert_state 1.7.1 N/A
    printf 'gdm3\tinstalled\t49\n' >>"$FACTS/dpkg"
    check 1.7.1
    assert_state 1.7.1 MANUAL
}

@test "manual: always MANUAL, with the evidence collected" {
    fx hardened
    check 2.1.23
    assert_state 2.1.23 MANUAL
    [[ "$(evidence_of 2.1.23)" == *"0.0.0.0:22"* ]]
}

@test "manual: listeners outside APPROVED_LISTENERS are flagged as evidence" {
    fx hardened
    printf 'APPROVED_LISTENERS=tcp:22\n' >"$FX/site.conf"
    check 2.1.23 --config "$FX/site.conf"
    [[ "$(evidence_of 2.1.23)" == *"NOT in APPROVED_LISTENERS: tcp 0.0.0.0:80"* ]]
}

# ---- svc_enabled_active ----------------------------------------------------------------------------
@test "svc_enabled_active: PASS, FAIL when inactive, N/A for the other time daemon" {
    fx hardened
    check 2.3.3.3
    assert_state 2.3.3.3 PASS
    sed -i '/^chrony.service/d' "$FACTS/units_all"
    check 2.3.3.3
    assert_state 2.3.3.3 FAIL
    check 2.3.2.2
    assert_state 2.3.2.2 N/A
}

@test "svc_enabled_active: journald only needs to be active (6.1.1.1.1)" {
    fx hardened
    check 6.1.1.1.1
    assert_state 6.1.1.1.1 PASS
}

@test "svc_enabled_active: cron rules are N/A when cron is not installed (2.4.1.1)" {
    fx hardened
    sed -i '/^cron\t/d' "$FACTS/dpkg"
    check 2.4.1.1
    assert_state 2.4.1.1 N/A
}

# ---- apt_config ----------------------------------------------------------------------------------------
@test "apt_config: PASS, FAIL on a wrong value, FAIL when absent" {
    fx hardened
    check 1.2.1.12
    assert_state 1.2.1.12 PASS
    sed -i 's/AllowInsecureRepositories "0"/AllowInsecureRepositories "1"/' "$FACTS/apt_config"
    check 1.2.1.12
    assert_state 1.2.1.12 FAIL
    sed -i '/AllowInsecureRepositories/d' "$FACTS/apt_config"
    check 1.2.1.12
    assert_state 1.2.1.12 FAIL
}

@test "apt_config: Check-Date must be explicitly true (1.2.1.15)" {
    fx hardened
    check 1.2.1.15
    assert_state 1.2.1.15 PASS
    sed -i '/Check-Date/d' "$FACTS/apt_config"
    check 1.2.1.15
    assert_state 1.2.1.15 FAIL
}
