#!/bin/bash
#
# check-reexec-coverage: every struct syscallentry in syscalls/**/*.c
# that has a .sanitise = field must either:
#   (a) carry the static .flags = REEXEC_SANITISE_OK flag, or
#   (b) contain a /* Not REEXEC_SANITISE_OK: ... */ rejection comment
#       explaining why it cannot, or
#   (c) carry AVOID_REEXEC in its flags (hard exclusion), or
#   (d) be listed in the baseline below as a known-dynamic entry that
#       publishes REEXEC_OK per-invocation via rec->flags |= REEXEC_OK.
#
# Background: trinity's re-exec path feeds a sanitise-bearing entry a
# second time with only the recorded args.  A sanitise function is safe
# for re-exec if it is "contract-clean" -- it does not issue syscalls
# with observable effects outside its arg slots.  Entries that qualify
# statically receive REEXEC_SANITISE_OK.  Entries with arm-by-arm
# variation (some arms are clean, some are not) publish REEXEC_OK
# per-invocation and are tracked here as known-dynamic.
#
# The file-level grep currently used by the build (git grep -lF
# REEXEC_SANITISE_OK -- syscalls/) works at file granularity and
# counts rejection comments as coverage.  This gate closes that gap:
# it detects a new sanitise-bearing entry added without any of the
# four annotations above -- a silent audit hole that file-level grep
# cannot catch.
#
# At the time this gate was introduced: 327 sanitise-bearing entries,
# 301 statically flagged (REEXEC_SANITISE_OK), 20 with rejection
# comments, 6 known-dynamic (listed in the baseline below).  The
# baseline must never grow without a documented reason.
#
# Detection (entry-level, not file-level):
#   Walk struct syscallentry definitions via awk; for each definition
#   that contains .sanitise = but lacks REEXEC_SANITISE_OK,
#   "Not REEXEC_SANITISE_OK", and AVOID_REEXEC within its body, report
#   <file>:<entry-name>.  Diff the sorted report against the baseline.
#   Any entry absent from the baseline is a build error.
#   Any baseline entry that is no longer reported is stale (the entry
#   was cleaned up) and is also a build error (prune the baseline).
#
# The baseline (check-reexec-coverage.baseline) lists known-dynamic
# entries.  It should shrink over time, never grow.

set -u

NAME="check-reexec-coverage"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/check-reexec-coverage.baseline"

if [ ! -d "$ROOT/syscalls" ]; then
	echo "FAIL: $NAME: syscalls/ directory not found under $ROOT" >&2
	exit 1
fi

# Load baseline entries (format: <file>:<entry_name>, one per line,
# comments with # are ignored).
declare -A BASELINED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		entry="$(echo "$entry" | sed 's/[[:space:]]#.*$//' | sed 's/[[:space:]]*$//')"
		[ -z "$entry" ] && continue
		BASELINED["$entry"]=1
	done < "$BASELINE"
fi

# Scan all struct syscallentry blocks in syscalls/**/*.c.
# An entry is flagged when its body contains .sanitise = but lacks:
#   REEXEC_SANITISE_OK
#   Not REEXEC_SANITISE_OK
#   AVOID_REEXEC
SCAN_RESULT="$(mktemp)"
trap 'rm -f "$SCAN_RESULT" 2>/dev/null' EXIT

find "$ROOT/syscalls" -name '*.c' | LC_ALL=C sort | \
xargs awk '
/^struct syscallentry / {
	name = $3
	sub(/[[:space:]]*=.*$/, "", name)
	in_struct = 1
	has_sanitise = 0
	has_reexec = 0
	next
}
in_struct {
	if (/\.sanitise[[:space:]]*=/)   has_sanitise = 1
	if (/REEXEC_SANITISE_OK/)        has_reexec = 1
	if (/Not REEXEC_SANITISE_OK/)    has_reexec = 1
	if (/AVOID_REEXEC/)              has_reexec = 1
	if (/^};/) {
		if (has_sanitise && !has_reexec)
			print FILENAME ":" name
		in_struct = 0
	}
}
' | LC_ALL=C sort > "$SCAN_RESULT"

# Strip the ROOT prefix from paths so they are repo-relative.
# awk FILENAME is an absolute path when invoked from find | xargs.
REPO_ROOT_ESC="$(echo "$ROOT" | sed 's|/|\\/|g')"
sed -i "s|^$REPO_ROOT_ESC/||" "$SCAN_RESULT" 2>/dev/null || true

total_flagged=$(wc -l < "$SCAN_RESULT")

# Classify: new (not in baseline) and stale (in baseline but no longer flagged).
new_entries=()
declare -A SEEN=()

while IFS= read -r hit; do
	[ -z "$hit" ] && continue
	SEEN["$hit"]=1
	if [ -z "${BASELINED[$hit]+x}" ]; then
		new_entries+=("$hit")
	fi
done < "$SCAN_RESULT"

stale_entries=()
for key in "${!BASELINED[@]}"; do
	[ -z "${SEEN[$key]+x}" ] && stale_entries+=("$key")
done

# --- Stale baseline check ---
if [ "${#stale_entries[@]}" -gt 0 ]; then
	{
		echo "  ${#stale_entries[@]} baseline entry/entries are now clean"
		echo "  (the entry acquired REEXEC_SANITISE_OK, a rejection comment,"
		echo "  AVOID_REEXEC, or was removed).  Prune the baseline:"
		for e in "${stale_entries[@]}"; do echo "    $e"; done
		echo "  scripts/check-static/check-reexec-coverage.baseline"
	} >&2
	echo "FAIL: $NAME: ${#stale_entries[@]} stale baseline entry/entries"
	exit 1
fi

# --- New undocumented entries ---
if [ "${#new_entries[@]}" -gt 0 ]; then
	{
		echo "  ${#new_entries[@]} struct syscallentry block(s) have .sanitise ="
		echo "  but no REEXEC_SANITISE_OK, no rejection comment, no AVOID_REEXEC,"
		echo "  and are not listed in the baseline as known-dynamic:"
		for e in "${new_entries[@]}"; do echo "    $e"; done
		echo ""
		echo "  Each entry must be annotated.  Choose one of:"
		echo "    (a) Add .flags = REEXEC_SANITISE_OK if sanitise_* is contract-clean"
		echo "        (no out-of-scope syscalls; output buffers re-poisoned per re-exec)."
		echo "    (b) Add a /* Not REEXEC_SANITISE_OK: <reason> */ comment inside the"
		echo "        struct body if the sanitise function cannot qualify statically."
		echo "    (c) Add AVOID_REEXEC to .flags if the syscall must never be re-run."
		echo "    (d) Add to scripts/check-static/check-reexec-coverage.baseline with a"
		echo "        brief reason if sanitise_* publishes REEXEC_OK per-invocation via"
		echo "        rec->flags |= REEXEC_OK (known-dynamic).  Baseline must never grow"
		echo "        without explanation."
	} >&2
	echo "FAIL: $NAME: ${#new_entries[@]} undocumented sanitise-bearing entry/entries"
	exit 1
fi

baselined_n=${#BASELINED[@]}
echo "PASS: $NAME (flagged_total=${total_flagged} known_dynamic=${baselined_n})"
exit 0
