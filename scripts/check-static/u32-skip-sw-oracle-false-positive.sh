#!/bin/bash
#
# u32-skip-sw-oracle-false-positive: verify the update-path oracle for the
# cls_u32 SKIP_SW hnode refcount-leak uses delete-then-settle, not a direct
# RTM_DELTFILTER probe on hnode2 while the step-A knode is still live.
#
# Background:
#   do_u32_skip_sw_leak() tests two code paths:
#
#   Create-path (hnode1): SKIP_SW filter install fails immediately with no
#   live knode; a direct build_deltfilter_handle oracle on hnode1 is correct.
#
#   Update-path (hnode2): a healthy knode is installed first (step A, refcnt
#   2), then an update with SKIP_SW is attempted (step B).  The knode from
#   step A is still live when the hnode2 oracle runs, so hnode2->refcnt is
#   always >= 2 on both buggy AND fixed kernels — a direct oracle returns
#   -EBUSY unconditionally (false positive).
#
#   The correct fix:
#   1. Delete knode (RTM_DELTFILTER on knode handle, step C).
#   2. Probe hnode2 via settle_then_probe_hnode2_delete() with bounded backoff
#      so the RCU-deferred refcnt decrement can land before the verdict.
#
# What this check enforces:
#
#   INVARIANT A: settle_then_probe_hnode2_delete() must be defined (not merely
#   called) in the scanned source file.  If the helper is removed, the
#   update-path oracle reverts to an unchecked direct probe.
#
#   INVARIANT B: No line in the scanned file may both reference hnode2 in a
#   build_deltfilter_handle() call AND be immediately followed (within a
#   short window) by a u32_link_leak_detected atomic bump, without an
#   intervening settle_then_probe_hnode2_delete() call.  The awk walk
#   detects this "direct-probe-then-count" pattern and reports it.
#
#   INVARIANT C: The knode delete (build_deltfilter_handle with knode_h)
#   must appear in the file before settle_then_probe_hnode2_delete is called
#   (line-order check).  This ensures the settle call is not orphaned from
#   its preceding knode delete.
#
# Per prior gate-hardening conventions:
#   - Fail closed on zero scanned files (assert count >= 1).
#   - Exit non-zero on any invariant violation.
#   - The gate must be able to fire: it is verified against a synthetic
#     bad fragment in a self-test at the bottom.

set -u

NAME="u32-skip-sw-oracle-false-positive"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# --- File discovery -------------------------------------------------------

mapfile -t SRCFILES < <(
	find childops/net/tc -name 'qdisc-churn.c' -type f | sort
)

if [ "${#SRCFILES[@]}" -eq 0 ]; then
	echo "FAIL: $NAME: no scanned files found (childops/net/tc/qdisc-churn.c missing)" >&2
	exit 1
fi

fail=0
hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# --- INVARIANT A: settle helper must be defined ---------------------------
#
# Check that settle_then_probe_hnode2_delete is defined as a function
# (not just called) in each scanned file.

for f in "${SRCFILES[@]}"; do
	if ! grep -qE '^static int settle_then_probe_hnode2_delete\b' "$f"; then
		echo "FAIL: $NAME: $f: settle_then_probe_hnode2_delete not defined" >&2
		echo "  The update-path oracle settle helper is missing." >&2
		echo "  Without it, a direct build_deltfilter_handle on hnode2 will" >&2
		echo "  return -EBUSY on healthy kernels (false positive)." >&2
		fail=1
	fi
done

# --- INVARIANT B: no direct hnode2 probe -> leak count pattern -----------
#
# Walk each source file with awk.  Track three state bits:
#   saw_settle  - a settle_then_probe_hnode2_delete() call was seen
#   saw_direct  - a build_deltfilter_handle(... hnode2 ...) == -EBUSY line
#                 was seen WITHOUT a preceding settle call in scope
#
# A violation is flagged when u32_link_leak_detected is incremented and
# saw_direct is set but saw_settle is not set.
#
# The awk resets saw_settle when a new top-level function opens (depth
# returns to 0 after having been > 0) so the check is per-function.

awk_check() {
	awk '
	function report(file, lno, msg) {
		print file ":" lno ":" msg
	}
	BEGIN {
		depth = 0
		saw_settle = 0
		saw_direct = 0
		fn_start = 0
	}
	{
		# Track brace depth for function boundary detection.
		line = $0
		n_open = gsub(/\{/, "{", line)
		n_clos = gsub(/\}/, "}", line)
		prev_depth = depth
		depth += n_open - n_clos

		# Entering a new top-level function resets state.
		if (prev_depth == 0 && depth > 0) {
			saw_settle = 0
			saw_direct = 0
			fn_start = FNR
		}
		# Leaving a top-level function.
		if (prev_depth > 0 && depth == 0) {
			saw_settle = 0
			saw_direct = 0
		}

		# SETTLE call present — the correct pattern.
		if ($0 ~ /settle_then_probe_hnode2_delete[[:space:]]*\(/)
			saw_settle = 1

		# Direct probe on hnode2 without going through settle helper.
		# Pattern: build_deltfilter_handle(... hnode2 ...) result used.
		# We detect the *call* on hnode2; the == -EBUSY check may be on
		# the same line or the next (multiline if).
		if ($0 ~ /build_deltfilter_handle[^;]*hnode2/ && !saw_settle)
			saw_direct = 1

		# Leak counter incremented.
		if ($0 ~ /u32_link_leak_detected/) {
			if (saw_direct && !saw_settle) {
				report(FILENAME, FNR,
				    "u32_link_leak_detected bumped after direct " \
				    "build_deltfilter_handle(hnode2) without " \
				    "settle_then_probe_hnode2_delete (false positive)")
				saw_direct = 0
			}
		}
	}
	' "$@"
}

awk_check "${SRCFILES[@]}" > "$hits_tmp"

if [ -s "$hits_tmp" ]; then
	echo "FAIL: $NAME: direct hnode2 probe -> leak-count pattern detected:" >&2
	while IFS=':' read -r file lno msg; do
		echo "  $file:$lno: $msg" >&2
	done < "$hits_tmp"
	echo "" >&2
	echo "  Fix: delete the knode first (RTM_DELTFILTER on knode_h), then" >&2
	echo "  call settle_then_probe_hnode2_delete() for the hnode2 oracle." >&2
	fail=1
fi

# --- INVARIANT C: knode delete precedes settle call ----------------------
#
# Line-order check: build_deltfilter_handle(... knode_h ...) must appear
# before settle_then_probe_hnode2_delete in each scanned file.

for f in "${SRCFILES[@]}"; do
	knode_line="$(grep -n 'build_deltfilter_handle[^;]*knode_h' "$f" \
		| head -1 | cut -d: -f1)"
	settle_line="$(grep -n 'settle_then_probe_hnode2_delete[[:space:]]*(' "$f" \
		| grep -Ev ':([[:space:]]*\*|static )' \
		| head -1 | cut -d: -f1)"

	if [ -z "$settle_line" ]; then
		echo "FAIL: $NAME: $f: no call to settle_then_probe_hnode2_delete found" >&2
		fail=1
		continue
	fi
	if [ -z "$knode_line" ]; then
		echo "FAIL: $NAME: $f: no build_deltfilter_handle(knode_h) found" >&2
		echo "  The knode must be deleted before the hnode2 settle-probe." >&2
		fail=1
		continue
	fi
	if [ "$knode_line" -ge "$settle_line" ]; then
		echo "FAIL: $NAME: $f: knode delete (line $knode_line) does not" \
		     "precede settle call (line $settle_line)" >&2
		echo "  Step C (knode RTM_DELTFILTER) must come before step D" \
		     "(settle_then_probe_hnode2_delete)." >&2
		fail=1
	fi
done

# --- Self-test: verify the gate can fire ---------------------------------
#
# Construct a synthetic fragment that embodies the old false-positive
# pattern (direct build_deltfilter_handle on hnode2 -> leak count) and
# confirm the awk rule fires on it.  If the awk logic is broken and
# returns no hits, the gate itself is broken.

selftest_tmp="$(mktemp --suffix=.c)"
trap 'rm -f "$hits_tmp" "$selftest_tmp"' EXIT

cat > "$selftest_tmp" << 'SELFTEST_EOF'
/* synthetic bad fragment — old false-positive pattern */
static void bad_oracle(void) {
	__u32 hnode2 = 0x10000000U;
	if (build_deltfilter_handle(ctx, ifindex, hnode2, qhandle) == -EBUSY)
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn.u32_link_leak_detected,
				   1, __ATOMIC_RELAXED);
}
SELFTEST_EOF

selftest_hits="$(awk_check "$selftest_tmp")"
if [ -z "$selftest_hits" ]; then
	echo "FAIL: $NAME: self-test failed — gate did not fire on known-bad" \
	     "fragment (awk logic is broken)" >&2
	fail=1
fi

# --- Result ---------------------------------------------------------------

if [ "$fail" -ne 0 ]; then
	echo "FAIL: $NAME"
	exit 1
fi

echo "PASS: $NAME: delete-then-settle pattern verified in ${#SRCFILES[@]} file(s)"
exit 0
