#!/bin/bash
#
# procfs-writer-deny-overlap: gate that warn_allow_deny_overlap() in
# childops/fs/procfs-writer.c audits both its anchored (PREFIX/EXACT)
# and MATCH_SUFFIX deny-rule halves and produces a non-zero count of
# shadowed pairs.
#
# Background: warn_allow_deny_overlap() started life covering only
# anchored deny rules against anchored allow prefixes.  MATCH_SUFFIX
# deny rules (seven entries: /mem, /coredump_filter, the five
# cgroup.{subtree_control,procs,threads,max.depth,max.descendants}
# patterns) were never audited: the checker was structurally silent
# about whether any of the eight MATCH_PREFIX allow rules could shadow
# them.  The /sys/class/ allow prefix and the /mem suffix deny, for
# example, produce a pattern-level shadow -- /sys/class/<leaf>/mem
# satisfies both rules, allow wins, and the deny is never visible.
# Whether a writable regular file at such a path exists on the current
# machine is a runtime question this check does not answer; the defect
# is that the checker was silent by construction rather than
# deliberately quiet after inspection.
#
# The suffix half is audited by synthesis: for each (PREFIX allow,
# SUFFIX deny) pair, warn_allow_deny_overlap() builds the concrete
# path "<allow_prefix>x<deny_suffix>" and runs it through the live
# path_allowed() / path_denied() / path_prefiltered() trio.  If the
# path is admitted with the deny silently overridden, the warning is
# emitted.  This gate confirms:
#
#   1. The binary is present (build happened before check-static runs).
#   2. At startup, at least one MATCH_SUFFIX shadow pair is reported --
#      fail-close: a zero count means either the suffix loop was
#      deleted, the deny table was silently emptied, or the binary was
#      not rebuilt after the source change.
#   3. The suffix count matches the sealed baseline (7 deny suffixes x
#      8 allow prefixes = 56 pairs); a delta FAILs so that a silent
#      drift in the procfs deny table cannot pass undetected.  Update
#      BASELINE_SUFFIX_PAIRS in this script after a deliberate policy
#      change.
#   4. At least one anchored overlap warning OR zero is acceptable --
#      the anchored half is structurally exercised; current policy has
#      all anchored overlaps resolved by prefilter_rules[] so the count
#      is legitimately zero.  This gate does not re-check that half
#      beyond confirming the binary ran and the suffix half fired.
#
# Baseline: 56 suffix-shadow pairs.  Update BASELINE_SUFFIX_PAIRS in
# this script after a deliberate policy change.

set -u

NAME="procfs-writer-deny-overlap"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

# Expected suffix-pair count sealed at the time this gate was written.
# 7 MATCH_SUFFIX deny rules x 8 MATCH_PREFIX allow rules.
BASELINE_SUFFIX_PAIRS=56

BINARY="$ROOT/trinity"
if [ ! -x "$BINARY" ]; then
	echo "FAIL: $NAME: binary $BINARY not found -- run 'make' before check-static" >&2
	exit 1
fi

WORK="$(mktemp -d /tmp/trinity-deny-overlap.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

STDERR_FILE="$WORK/trinity.stderr"

# Run trinity long enough for procfs_writer_init() to emit the overlap
# warnings (it fires in the parent before fork_children).  --dry-run
# keeps the run deterministic and safe; a handful of iterations is
# enough for init to complete.
( cd "$WORK" && \
  TRINITY_NO_DMESG=1 timeout -k 5 15 \
      "$BINARY" --dry-run -C 1 -N 20 \
      >"$WORK/trinity.stdout" 2>"$STDERR_FILE" ) || true

if [ ! -s "$STDERR_FILE" ]; then
	echo "FAIL: $NAME: trinity produced no stderr output (binary did not start?)" >&2
	exit 1
fi

# Count suffix-shadow pairs: lines containing both "shadows suffix deny rule"
# and "procfs_writer: WARNING:" are the new-half warnings.
suffix_pairs=$(grep -c "procfs_writer: WARNING:.*shadows suffix deny rule" \
		    "$STDERR_FILE" 2>/dev/null || true)

fail=0

# Fail-close: zero suffix pairs means the suffix loop is broken or the
# deny table was emptied.  This is the primary gate the 524 lesson
# teaches: "a checker that emits nothing tells you nothing".
if [ "$suffix_pairs" -eq 0 ]; then
	echo "FAIL: $NAME: zero MATCH_SUFFIX shadow pairs audited -- suffix loop" \
	     "is missing or deny_rules[] MATCH_SUFFIX entries were deleted" >&2
	fail=1
fi

# Hard fail on count delta: a mismatch signals a policy change (add/remove
# deny or allow entry) or a bug in the synthesizer.  Update
# BASELINE_SUFFIX_PAIRS in this script after a deliberate policy change.
if [ "$suffix_pairs" -ne "$BASELINE_SUFFIX_PAIRS" ]; then
	echo "FAIL: $NAME: suffix shadow pair count changed:" \
	     "expected=$BASELINE_SUFFIX_PAIRS got=$suffix_pairs" \
	     "(update BASELINE_SUFFIX_PAIRS in this script after a deliberate" \
	     "policy change)" >&2
	fail=1
fi

if [ "$fail" -eq 1 ]; then
	echo "FAIL: $NAME (suffix_pairs=$suffix_pairs)"
	exit 1
fi

echo "PASS: $NAME (suffix_pairs=$suffix_pairs)"
exit 0
