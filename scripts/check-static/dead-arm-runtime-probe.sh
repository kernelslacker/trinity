#!/bin/bash
#
# dead-arm-runtime-probe: verify that the access-after-cap-drop runtime
# dead-arm probes exist and are wired into the dead-arm reporting surface
# for tracefs-fuzzer and afxdp-churn.
#
# Background: dead-arm-config.sh catches CONFIG_*-gated arms at build
# time, but two classes of arm are config-live and runtime-dead:
#
#   tracefs-fuzzer: CONFIG_FTRACE=y / kernel has tracefs, but the fuzz
#     user's capability set after cap-drop does not allow writes.
#     Probe: access(tracefs_root/tracing_on, W_OK) in child context.
#
#   afxdp-churn: CONFIG_XDP_SOCKETS=y but socket(AF_XDP) returns EPERM/
#     EACCES because the fuzz user lacks CAP_NET_RAW after cap-drop.
#     Probe: errno check on socket(AF_XDP) → ns_cap_denied_afxdp latch.
#
# Each check below requires at least one match.  Fail-closed: zero
# matches is a hard FAIL, not a silent pass.  This guards against the
# probes being accidentally removed or the wiring silently dropped.
#
# Severity: FAIL (exit 1) -- these probes are part of the correctness
# contract for the dead-arm detection surface.

set -u

NAME="dead-arm-runtime-probe"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

fail_count=0

check_match() {
	local label="$1"
	local file="$2"
	local pattern="$3"
	local count

	count=$(grep -cE "$pattern" "$file" 2>/dev/null || true)
	if [ "${count:-0}" -eq 0 ]; then
		echo "FAIL: $NAME: $label: pattern '$pattern' not found in $file" >&2
		fail_count=$((fail_count + 1))
	fi
}

# ---- tracefs-fuzzer: access(W_OK) probe in child context ----

# The probe performs access(..., W_OK) on the tracefs tracing_on file
# from within tracefs_fuzzer() (child context, after cap-drop).
check_match \
	"tracefs W_OK probe present" \
	"childops/fs/tracefs-fuzzer.c" \
	"access\(.*W_OK\)"

# The probe increments runtime_cap_denied on EACCES/EPERM.
check_match \
	"tracefs runtime_cap_denied increment" \
	"childops/fs/tracefs-fuzzer.c" \
	"runtime_cap_denied"

# The field exists in the stats struct.
check_match \
	"tracefs runtime_cap_denied stats field" \
	"stats/subsys/tracefs_fuzzer.h" \
	"runtime_cap_denied"

# The dead-arm check picks up the counter in dump_stats_dead_arm_check().
check_match \
	"tracefs dead-arm check wired in subsystems.c" \
	"stats/dump/subsystems.c" \
	"tracefs_fuzzer\.runtime_cap_denied"

# The JSON emitter covers the tracefs runtime_dead case.
check_match \
	"tracefs JSON dead-arm emitter in tail.c" \
	"stats/json/tail.c" \
	"tracefs_fuzzer.*runtime_cap_denied|runtime_cap_denied.*tracefs_fuzzer"

# ---- afxdp-churn: ns_cap_denied_afxdp socket(EPERM/EACCES) probe ----

# The latch is declared in the internal header.
check_match \
	"afxdp ns_cap_denied_afxdp declared in internal header" \
	"childops/net/afxdp-churn-internal.h" \
	"ns_cap_denied_afxdp"

# The latch is set in afxdp-churn-umem.c when socket() returns EPERM/EACCES.
check_match \
	"afxdp ns_cap_denied_afxdp set on EPERM/EACCES" \
	"childops/net/afxdp-churn-umem.c" \
	"ns_cap_denied_afxdp"

# The new setup_failed_cap_denied counter exists in the stats struct.
check_match \
	"afxdp setup_failed_cap_denied stats field" \
	"stats/subsys/afxdp_churn.h" \
	"setup_failed_cap_denied"

# The early-bail in afxdp_churn() checks the latch.
check_match \
	"afxdp cap-denied early bail in afxdp-churn.c" \
	"childops/net/afxdp-churn.c" \
	"ns_cap_denied_afxdp"

# dump_stats_dead_arm_check() emits RUNTIME_DEAD_ARM for the cap-denied case.
check_match \
	"afxdp RUNTIME_DEAD_ARM wired in subsystems.c" \
	"stats/dump/subsystems.c" \
	"setup_failed_cap_denied"

# The JSON emitter covers the afxdp cap-denied runtime_dead case.
check_match \
	"afxdp JSON runtime_dead emitter in tail.c" \
	"stats/json/tail.c" \
	"setup_failed_cap_denied"

# ---- ARM_VERDICT_RUNTIME_DEAD in the shared verdict enum ----
check_match \
	"ARM_VERDICT_RUNTIME_DEAD in arm-verdict.h" \
	"stats/arm-verdict.h" \
	"ARM_VERDICT_RUNTIME_DEAD"

# ---- Final verdict ----

if [ "$fail_count" -gt 0 ]; then
	echo "FAIL: $NAME: $fail_count check(s) failed -- runtime dead-arm probes missing or unwired"
	exit 1
fi

echo "PASS: $NAME: all runtime dead-arm probe checks present and wired"
exit 0
