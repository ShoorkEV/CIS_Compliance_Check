#!/usr/bin/env bash
# usage: tests/run_fixture.sh <fixture> [cis-audit.sh args...]
# Runs the audit against a recorded fixture (test mode: no root/OS checks, no commands).
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fx=$here/fixtures/$1
shift
CIS_AUDIT_TESTMODE=1 CIS_AUDIT_FACTS_DIR=$fx/facts CIS_AUDIT_ROOTFS=$fx/rootfs \
    bash "$here/../cis-audit.sh" "$@"
