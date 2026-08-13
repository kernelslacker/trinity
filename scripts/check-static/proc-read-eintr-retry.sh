#!/bin/bash
#
# proc-read-eintr-retry: reject open/read/pread calls on /proc paths (or via
# pidstatfiles[] fds) that are NOT wrapped in TEMP_FAILURE_RETRY.
#
# Trinity children take SIGALRM once per second (health/signals.c installs
# SIGALRM without SA_RESTART).  An unretried EINTR from open/read/pread on
# /proc is treated by callers as "pid is dead", causing false reap decisions
# and silently-dropped D-state diagnostics: get_pid_state() returns '?'
# instead of 'D', so the reap-watchdog D-state branch at main/reap-watchdog.c
# is never taken.
#
# close() is deliberately NOT covered here: retrying close() after EINTR on
# Linux is the double-close bug and could close an unrelated file descriptor.
#
# Two detection patterns (checked per source line):
#   (A) open/read/pread with a "/proc" path literal in the argument list.
#   (B) read/pread with pidstatfiles[ as the first argument (the fd variable
#       used by get_pid_state() in main/reap.c for the per-child stat poll).
# A match is a FAIL iff the line does NOT also contain TEMP_FAILURE_RETRY.
#
# Scoped directories: main/ dispatch/ utils/
# The scope list is explicit so that a future refactor moving pids.c out of
# dispatch/ surfaces as a visible FAIL (zero files scanned → fail-closed)
# rather than a silent zero-hit PASS.

set -u

NAME="proc-read-eintr-retry"
ROOT="${REPO_ROOT:-$(pwd)}"

# Directories to scan.  If any of these disappears or is renamed, the
# scanned-file assertion below will catch it.
SCAN_DIRS="main dispatch utils"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

scanned=0

while IFS= read -r srcfile; do
    scanned=$((scanned + 1))

    # Pattern A: open/read/pread call whose argument list contains "/proc
    # Pattern B: read/pread call whose first argument is pidstatfiles[
    # In both cases, the line must NOT already contain TEMP_FAILURE_RETRY.
    grep -E -n \
        '\b(open|read|pread)[[:space:]]*\([^)]*"/proc|[[:space:](](p?read)[[:space:]]*\([[:space:]]*pidstatfiles\[' \
        "$srcfile" 2>/dev/null \
    | grep -v 'TEMP_FAILURE_RETRY' \
    | while IFS=: read -r lineno content; do
        # Skip comment lines (block-comment body or line comment).
        trimmed="${content#"${content%%[![:space:]]*}"}"
        case "$trimmed" in
            \**|/\**|//*) continue ;;
        esac
        echo "${srcfile}:${lineno}: ${content}"
    done
done < <(
    for d in $SCAN_DIRS; do
        find "$d" -name '*.c' -type f 2>/dev/null
    done | sort
) >> "$hits_tmp"

# Fail-closed: if the glob found nothing, SCAN_DIRS is broken or empty.
if [ "$scanned" -eq 0 ]; then
    echo "FAIL: $NAME: no .c files found under [${SCAN_DIRS}] — directory layout changed?" >&2
    echo "FAIL: $NAME: 0 files scanned (fail-closed)"
    exit 1
fi

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
    {
        echo "  $NAME: open/read/pread on /proc (or pidstatfiles[]) not wrapped"
        echo "  in TEMP_FAILURE_RETRY — SIGALRM EINTR will be misread as pid-dead:"
        sed 's/^/    /' "$hits_tmp"
        echo "  fix: wrap each call in TEMP_FAILURE_RETRY(...)."
        echo "  NOTE: do NOT wrap close() — retrying close() after EINTR on Linux"
        echo "  is the double-close bug and may close an unrelated fd."
    } >&2
    echo "FAIL: $NAME: $n bare /proc open/read/pread site(s) (${scanned} files scanned)"
    exit 1
fi

echo "PASS: $NAME: 0 bare /proc open/read/pread site(s) (${scanned} files scanned)"
exit 0
