#!/usr/bin/env bash
# tests/make_fixtures_variant.sh - sourced by make_fixtures.sh after the hardened fixture.
# "variant" = hardened + rsyslog as the logger + systemd-timesyncd instead of chrony.
# It exercises the alternative branches (applicability: LOGGER, TIME_DAEMON).
# SYNTHETIC, like the other fixtures.
# shellcheck disable=SC2154

cp -r "$OUT/hardened" "$OUT/variant"
F=$OUT/variant/facts
RF=$OUT/variant/rootfs
W "$RF/proc/sys/kernel/hostname" <<'EOF'
cis-variant
EOF
sed -i '/^chrony\t/d' "$F/dpkg"
printf 'rsyslog\tinstalled\t8.2504.0-1\nsystemd-timesyncd\tinstalled\t258-1\n' >>"$F/dpkg"
sed -i '/^chrony.service/d' "$F/unit_files" "$F/units_all"
printf 'rsyslog.service\tenabled\tenabled\nsystemd-timesyncd.service\tenabled\tenabled\n' >>"$F/unit_files"
printf 'rsyslog.service loaded active running System Logging Service\nsystemd-timesyncd.service loaded active running Network Time Synchronization\n' >>"$F/units_all"
: >"$F/ps_chronyd"
W "$F/catcfg.systemd_timesyncd.conf" <<'EOF'
# /usr/lib/systemd/timesyncd.conf
[Time]
#NTP=
#FallbackNTP=ntp.ubuntu.com

# /etc/systemd/timesyncd.conf.d/60-cis.conf
[Time]
NTP=ntp.example.org
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
ForwardToSyslog=yes
EOF
W "$RF/etc/rsyslog.conf" <<'EOF'
$FileCreateMode 0640
# module(load="imudp")
# module(load="imtcp")
*.* action(type="omfwd" target="loghost.example.org" port="514" protocol="tcp")
EOF
mkdir -p "$RF/etc/rsyslog.d" "$RF/etc/logrotate.d"
printf 'weekly\nrotate 4\n' >"$RF/etc/logrotate.conf"
rm -rf "$RF/etc/chrony"
printf 'variant fixture written to %s\n' "$OUT/variant"
