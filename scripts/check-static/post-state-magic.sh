#!/bin/bash
#
# post-state-magic: every `struct *_post_state` in syscalls/ should
# begin with `unsigned long magic` and ship a matching
# `*_POST_STATE_MAGIC` constant in the same file.
#
# This is the convention that distinguishes a valid post_state region
# from arbitrary attacker-influenced memory.  The ppoll bad-free
# regression that motivated this check was exactly a post_state that
# lacked a cookie: a stale or corrupt pointer could not be recognised
# as not-a-post_state and was happily freed.
#
# The repo contains a baseline of grandfathered post_state structs
# that predate the convention; those are accepted as-is.  The baseline
# should shrink over time, never grow.  A new post_state added without
# a cookie fails the check.

set -u

NAME="post-state-magic"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/post-state-magic.baseline"

# Build a set of grandfathered file:tag pairs from the baseline.
# Strip comments and blanks.
declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

# Walk every syscalls/*.c, find struct *_post_state definitions, and
# verify each has `unsigned long magic` within the first ~30 lines.
# Then verify that a *_POST_STATE_MAGIC macro exists in the same file
# (case-insensitive on the tag, since tags use lowercase but MAGIC
# names are uppercase).
missing_magic=()
new_unbaselined=()
removed_baseline=()

# Track what we saw so we can flag stale baseline entries (struct was
# hardened or removed but still listed in the baseline).
declare -A SEEN_KEY=()

while IFS= read -r srcfile; do
	# Extract every `struct foo_post_state {` and inspect its body.
	awk -v file="${srcfile#"$ROOT"/}" '
		BEGIN { in_struct = 0 }
		/^struct [a-zA-Z0-9_]+_post_state \{/ {
			match($0, /^struct ([a-zA-Z0-9_]+)_post_state \{/, m)
			tag = m[1]
			in_struct = 1
			lookahead = 0
			has_magic = 0
			next
		}
		in_struct {
			lookahead++
			if ($0 ~ /^[[:space:]]*unsigned long magic[[:space:]]*;/)
				has_magic = 1
			if ($0 ~ /^\};/ || lookahead > 30) {
				print file ":" tag ":" (has_magic ? "Y" : "N")
				in_struct = 0
			}
		}
	' "$srcfile"
done < <(find "$ROOT/syscalls" -name '*.c' -print | sort) | while IFS=':' read -r file tag has_magic; do
	key="$file:$tag"
	echo "SEEN $key"

	if [ "$has_magic" = "Y" ]; then
		# Has magic field.  Verify matching *_POST_STATE_MAGIC macro
		# exists in the same source file.  Uppercase the tag.
		upper=$(echo "$tag" | tr '[:lower:]' '[:upper:]')
		if ! grep -q "^#define[[:space:]]\+${upper}_POST_STATE_MAGIC" "$ROOT/$file"; then
			echo "MISSING_MAGIC $key"
		fi
	else
		if [ -n "${GRANDFATHERED[$key]+x}" ]; then
			echo "GRAND $key"
		else
			echo "NEW $key"
		fi
	fi
done > /tmp/.check-static-post-state.$$ 2>/dev/null

# Replay the marker output.
while IFS=' ' read -r kind key; do
	case "$kind" in
		SEEN)
			SEEN_KEY["$key"]=1
			;;
		MISSING_MAGIC)
			missing_magic+=("$key")
			;;
		NEW)
			new_unbaselined+=("$key")
			;;
	esac
done < /tmp/.check-static-post-state.$$
rm -f /tmp/.check-static-post-state.$$

# Baseline entries that no longer correspond to a real struct are
# stale and should be removed.  This is a non-fatal advisory because
# someone may have hardened a struct in the same commit they ran the
# check.  Surface it on stderr but don't fail.
for entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_KEY[$entry]+x}" ]; then
		removed_baseline+=("$entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} post_state struct(s) lack 'unsigned long magic' and are not in the baseline:"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo "  fix: add 'unsigned long magic;' as first field and define <TAG>_POST_STATE_MAGIC,"
		echo "       OR (only if hardening is deferred) add the line to scripts/check-static/post-state-magic.baseline"
	} >&2
fi

if [ "${#missing_magic[@]}" -gt 0 ]; then
	{
		echo "  ${#missing_magic[@]} post_state struct(s) have 'magic' field but no matching *_POST_STATE_MAGIC macro:"
		for e in "${missing_magic[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#removed_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#removed_baseline[@]} baseline entry/entries no longer match a struct (consider pruning):"
		for e in "${removed_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_unbaselined[@]}" -gt 0 ] || [ "${#missing_magic[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} new without cookie, ${#missing_magic[@]} missing MAGIC macro"
	exit 1
fi

baseline_size=${#GRANDFATHERED[@]}
total=${#SEEN_KEY[@]}
hardened=$((total - baseline_size))
echo "PASS: $NAME (total=$total, hardened=$hardened, grandfathered=$baseline_size)"
exit 0
