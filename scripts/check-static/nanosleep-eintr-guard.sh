#!/bin/bash
#
# nanosleep-eintr-guard: reject (void)nanosleep() in childops/ files that
# also contain an arm_done latch (oracle-grade verdict paths).
#
# Trinity children receive SIGALRM once per second (child/child.c arms
# SIGALRM without SA_RESTART).  nanosleep() called with rem=NULL discards
# the unslept remainder on EINTR without surfacing it — the caller cannot
# tell how much sleep was lost.  In a verdict-bearing settle loop (one
# whose result gates a latching arm_done stat bump) a truncated nanosleep
# can cause the loop to declare -EBUSY before the RCU-deferred work item
# has run, producing a false-positive that latches the arm permanently and
# silences the leak detector for the rest of the run.
#
# Scope: childops/ files that contain "_arm_done" — these are the oracle-
# grade paths where a misread -EBUSY has lasting consequences.  Pacing
# sleeps in files without arm_done latches are deliberately excluded: their
# EINTR truncation is harmless (a slightly shorter wait, not a wrong verdict).
#
# The correct fix is one of:
#   (A) deadline-based loop with clock_gettime(CLOCK_MONOTONIC): EINTR
#       can shorten a sleep slice but cannot shorten the deadline, so the
#       full settle window always elapses on the wall clock.
#   (B) nanosleep-with-rem retry:
#         struct timespec rem = gap;
#         while (nanosleep(&rem, &rem) < 0 && errno == EINTR) ;
#
# Do NOT use TEMP_FAILURE_RETRY: that macro retries on -1/errno, not on
# the rem-argument pattern, and does not propagate the remaining sleep.
#
# Related: proc-read-eintr-retry.sh covers open/read/pread on /proc; this
# script covers the nanosleep blind spot that proc-read-eintr-retry cannot
# see (cf. childops/fs/statmount-idmap-overflow.c SIGALRM bleed-through
# comment and the wave-contradicts-itself instance in qdisc-churn.c).

set -u

NAME="nanosleep-eintr-guard"
ROOT="${REPO_ROOT:-$(pwd)}"
SCAN_DIR="childops"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

if [ ! -d "$SCAN_DIR" ]; then
    echo "FAIL: $NAME: scan directory '$SCAN_DIR' not found — layout changed?" >&2
    echo "FAIL: $NAME: 0 files scanned (fail-closed)"
    exit 1
fi

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

scanned=0
oracle_files=0

while IFS= read -r srcfile; do
    scanned=$((scanned + 1))

    # Only check oracle-grade files: those containing an _arm_done latch.
    # Pacing sleeps in files without arm_done latches are benign (a slightly
    # shorter wait does not flip a verdict).
    if ! grep -q '_arm_done' "$srcfile" 2>/dev/null; then
        continue
    fi
    oracle_files=$((oracle_files + 1))

    # Match (void)nanosleep( — the cast-to-void pattern confirms the return
    # value (and thus the EINTR signal) is being silently discarded.
    grep -E -n '\(void\)[[:space:]]*nanosleep[[:space:]]*\(' "$srcfile" 2>/dev/null \
    | while IFS=: read -r lineno content; do
        # Skip comment lines.
        trimmed="${content#"${content%%[![:space:]]*}"}"
        case "$trimmed" in
            \**|/\**|//*) continue ;;
        esac
        echo "${srcfile}:${lineno}: ${content}"
    done
done < <(find "$SCAN_DIR" -name '*.c' -type f | sort) >> "$hits_tmp"

if [ "$scanned" -eq 0 ]; then
    echo "FAIL: $NAME: no .c files found under ${SCAN_DIR}/ — directory layout changed?" >&2
    echo "FAIL: $NAME: 0 files scanned (fail-closed)"
    exit 1
fi

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
    {
        echo "  $NAME: (void)nanosleep() in an oracle-grade childop (has _arm_done latch)"
        echo "  discards EINTR remainder.  SIGALRM (no SA_RESTART) truncates the sleep"
        echo "  silently, producing a false-positive -EBUSY that latches the arm"
        echo "  permanently and silences the detector for the rest of the run."
        echo "  Use a deadline loop with clock_gettime(CLOCK_MONOTONIC), or retry"
        echo "  with the rem argument:"
        echo "    struct timespec rem = gap;"
        echo "    while (nanosleep(&rem, &rem) < 0 && errno == EINTR) ;"
        sed 's/^/    /' "$hits_tmp"
    } >&2
    echo "FAIL: $NAME: $n bare (void)nanosleep site(s) in oracle childops (${scanned} files scanned, ${oracle_files} oracle)"
    exit 1
fi

echo "PASS: $NAME: 0 bare (void)nanosleep site(s) in oracle childops (${scanned} files scanned, ${oracle_files} oracle)"
exit 0
