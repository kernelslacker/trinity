#!/bin/bash
#
# nested-writable-len: flag nested get_writable_struct/long_string
# allocations that are stored straight into a field of an outer struct
# without a NULL check.
#
# Trinity sanitisers commonly allocate a parent ioctl payload struct
# via get_writable_struct() and NULL-check it, then allocate a sibling
# data buffer and assign it into a field of the parent (e.g.
#     parent->buf = get_writable_struct(len);
#     parent->len = len;
# ).  When the inner allocator returns NULL but the matching length
# field stays non-zero, the kernel ioctl handler reads through a NULL
# pointer with a plausible length and either faults or worse.
#
# The correct shape stashes the inner alloc in a local, NULL-checks
# it, and only then writes the field (and the length).  See
# ioctls/nvme.c for the canonical pattern after fixing.
#
# This check is a regex tripwire, not a full analyser: it grep-matches
# the assignment shape
#     (->|[)<field> = get_writable_(struct|long_string)(
# and compares the resulting path:line list against a baseline of
# currently-known violators.  New violators not in the baseline fail
# the check.  As fixes land, the corresponding baseline lines must be
# removed in the same commit -- a stale baseline entry also fails.
# The baseline therefore shrinks monotonically toward zero.

set -u

NAME="nested-writable-len"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/nested-writable-len.baseline"

PATTERN='(->|\[)[a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*get_writable_(struct|long_string)[[:space:]]*\('

# Collect current matches as "path:line" relative to repo root,
# skipping obvious comment / string-literal lines.
current_tmp="$(mktemp)"
trap 'rm -f "$current_tmp" "$baseline_tmp"' EXIT
baseline_tmp="$(mktemp)"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

while IFS= read -r srcfile; do
	# grep -E -n, print as path:line:content, then filter and reformat.
	grep -E -n "$PATTERN" "$srcfile" 2>/dev/null | \
	while IFS=: read -r lineno rest; do
		# $rest is the raw source line.  Trim leading whitespace and
		# skip if it begins with a comment marker.  This intentionally
		# does not attempt full C lexing; it just drops the most common
		# false positives (a banner comment quoting the pattern, or a
		# // line annotation).
		trimmed="${rest#"${rest%%[![:space:]]*}"}"
		case "$trimmed" in
			\**|/\**|//*) continue ;;
		esac
		echo "${srcfile#./}:$lineno"
	done
done < <(find . -name '*.c' -type f -not -path './.git/*' | sort) | sort -u > "$current_tmp"

# Read baseline, stripping comments and blanks.
if [ -r "$BASELINE" ]; then
	sed -e 's/#.*$//' -e 's/[[:space:]]\+$//' "$BASELINE" \
		| grep -v '^[[:space:]]*$' \
		| sort -u > "$baseline_tmp"
else
	: > "$baseline_tmp"
fi

# New violators: in current but not in baseline.
new_violators="$(comm -23 "$current_tmp" "$baseline_tmp")"
# Stale baseline: in baseline but not in current.
stale_baseline="$(comm -13 "$current_tmp" "$baseline_tmp")"

fail=0

if [ -n "$new_violators" ]; then
	fail=1
	{
		echo "  $NAME: new nested-writable allocation(s) missing NULL check:"
		echo "$new_violators" | sed 's/^/    /'
		echo "  fix: stash the inner get_writable_struct() result in a local,"
		echo "       NULL-check it, and only then assign into the parent field"
		echo "       (and the matching length).  See ioctls/nvme.c for the pattern."
		echo "       If the fix is genuinely deferred, add the path:line to"
		echo "       scripts/check-static/nested-writable-len.baseline."
	} >&2
fi

if [ -n "$stale_baseline" ]; then
	fail=1
	{
		echo "  $NAME: baseline entry/entries no longer match a violator -"
		echo "  please remove from $BASELINE:"
		echo "$stale_baseline" | sed 's/^/    /'
	} >&2
fi

total_current="$(wc -l < "$current_tmp" | tr -d ' ')"
total_baseline="$(wc -l < "$baseline_tmp" | tr -d ' ')"

if [ "$fail" -ne 0 ]; then
	echo "FAIL: $NAME (current=$total_current, baseline=$total_baseline)"
	exit 1
fi

echo "PASS: $NAME (grandfathered=$total_baseline)"
exit 0
