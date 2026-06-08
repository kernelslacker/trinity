#!/bin/bash
#
# post-state-ownership: every .sanitise handler that stamps a
# *_POST_STATE_MAGIC cookie into a freshly-allocated struct and
# installs it into rec->post_state must also register the chunk in
# the post_state ownership table.
#
# Sibling check to post-state-magic.sh (which validates the STRUCT
# definition carries `unsigned long magic`) and post-state-deref.sh
# (which validates the USE SITE consults the cookie before chasing the
# pointer).  This one closes the third leg: the SETUP SITE must wire
# the snap into the ownership table so the .post handler's
# post_state_is_owned() / post_state_claim_owned() gate has something
# to verify against.
#
# The bug class this catches is the magic-only holdout: a handler
# that stamps snap->magic, assigns rec->post_state, and then in .post
# relies on the cookie alone -- a sibling stomp can redirect
# rec->post_state at a foreign chunk that happens to carry a matching
# cookie value (in-flight sibling snap, stale deferred-free slot not
# yet evicted, coincidental same-bucket alloc) and the magic compare
# clears the wrong struct.  Only the ownership-table lookup proves
# the pointer references THIS attempt's snapshot.  See utils.c
# post_state_install / post_state_claim_owned for the helper bracket
# and execve.c for the equivalent hand-rolled register pair.
#
# Heuristic: for each function named on a `.sanitise = HANDLER,` line
# in syscalls/, parse the function body.  If the body contains a
# `*_POST_STATE_MAGIC` token (the magic stamp is the signal that a
# post_state struct is being created here), it must also contain
# either:
#
#   post_state_install(...)         -- the canonical helper
#   post_state_register(...)        -- the manual equivalent
#
# A handler with the magic stamp but neither register call is the
# holdout shape and is flagged.
#
# A baseline of grandfathered handlers lives alongside this script as
# post-state-ownership.baseline (one `file:funcname` per line).  The
# baseline should shrink over time, never grow.

set -u

NAME="post-state-ownership"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/post-state-ownership.baseline"

declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

# Collect every .sanitise symbol referenced from any `.sanitise = NAME,`
# assignment in syscalls/.  The handler definition may live in the same
# file or a sibling, so we treat the set as a global symbol table.
SAN_NAMES_FILE="$(mktemp)"
RESULTS_FILE="$(mktemp)"
trap 'rm -f "$SAN_NAMES_FILE" "$RESULTS_FILE" 2>/dev/null' EXIT

grep -hE '^[[:space:]]*\.sanitise[[:space:]]*=' "$ROOT"/syscalls/*.c \
	| sed -e 's/.*\.sanitise[[:space:]]*=[[:space:]]*//' \
	      -e 's/[[:space:],].*//' \
	| sort -u > "$SAN_NAMES_FILE"

# Per-file scan.  awk extracts each function whose name is in the
# sanitise set, runs the ownership-presence heuristic on its body.
while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"
	awk -v file="$rel" -v sans_file="$SAN_NAMES_FILE" '
	BEGIN {
		while ((getline n < sans_file) > 0)
			if (n != "") is_san[n] = 1
		close(sans_file)
		state = 0       # 0 = scanning, 1 = inside sanitise body
		depth = 0
	}
	function brace_delta(s,    i, c, opens, closes, in_str, in_chr, in_blk) {
		opens = 0; closes = 0
		in_str = 0; in_chr = 0; in_blk = 0
		for (i = 1; i <= length(s); i++) {
			c = substr(s, i, 1)
			if (in_blk) {
				if (c == "*" && substr(s, i+1, 1) == "/") {
					in_blk = 0; i++
				}
				continue
			}
			if (in_str) {
				if (c == "\\") { i++; continue }
				if (c == "\"") in_str = 0
				continue
			}
			if (in_chr) {
				if (c == "\\") { i++; continue }
				if (c == "\x27") in_chr = 0
				continue
			}
			if (c == "/" && substr(s, i+1, 1) == "*") {
				in_blk = 1; i++; continue
			}
			if (c == "/" && substr(s, i+1, 1) == "/") break
			if (c == "\"") { in_str = 1; continue }
			if (c == "\x27") { in_chr = 1; continue }
			if (c == "{") opens++
			else if (c == "}") closes++
		}
		return opens - closes
	}
	function strip_comments(s,    out, i, c, n) {
		# Track /* ... */ block-comment state across lines via the
		# file-scope in_block_comment flag so a multi-paragraph
		# comment cannot leak tokens (_POST_STATE_MAGIC,
		# post_state_register) into the scanner.  Also strip //
		# line comments.
		out = ""
		n = length(s)
		i = 1
		while (i <= n) {
			c = substr(s, i, 1)
			if (in_block_comment) {
				if (c == "*" && substr(s, i+1, 1) == "/") {
					in_block_comment = 0
					i += 2
					continue
				}
				i++
				continue
			}
			if (c == "/" && substr(s, i+1, 1) == "*") {
				in_block_comment = 1
				i += 2
				continue
			}
			if (c == "/" && substr(s, i+1, 1) == "/") break
			out = out c
			i++
		}
		return out
	}
	function reset_state() {
		cur_fname = ""
		cur_has_magic_stamp = 0
		cur_has_register = 0
		in_block_comment = 0
	}
	function analyze_line(line,    code) {
		code = strip_comments(line)

		# Magic-cookie stamp: the marker that a post_state struct is
		# being created in this body.  Matches both the assign
		# (`snap->magic = FOO_POST_STATE_MAGIC`) and any other token
		# use of the constant; either is sufficient evidence.
		if (code ~ /_POST_STATE_MAGIC/) cur_has_magic_stamp = 1

		# Either ownership-table wiring call is sufficient.
		if (code ~ /post_state_install[[:space:]]*\(/) cur_has_register = 1
		if (code ~ /post_state_register[[:space:]]*\(/) cur_has_register = 1
	}
	{
		if (state == 0) {
			if (match($0, /^[[:space:]]*static[[:space:]].*[[:space:]\*]([A-Za-z_][A-Za-z0-9_]+)[[:space:]]*\(/, m)) {
				fname = m[1]
				if (fname in is_san) {
					reset_state()
					cur_fname = fname
					state = 1
					depth = 0
				}
			}
		}
		if (state == 1) {
			analyze_line($0)
			depth += brace_delta($0)
			if (depth <= 0 && $0 ~ /\}/) {
				if (cur_has_magic_stamp) {
					if (cur_has_register) {
						print "BRACKETED " file ":" cur_fname
					} else {
						print "HOLDOUT " file ":" cur_fname
					}
				}
				state = 0
				depth = 0
				reset_state()
			}
		}
	}
	' "$srcfile"
done < <(find "$ROOT/syscalls" -name '*.c' -print | sort) > "$RESULTS_FILE"

new_holdouts=()
declare -A SEEN_HOLDOUT=()
declare -A SEEN_ANY=()

while IFS=' ' read -r kind key; do
	case "$kind" in
		BRACKETED)
			SEEN_ANY["$key"]=1
			;;
		HOLDOUT)
			SEEN_ANY["$key"]=1
			SEEN_HOLDOUT["$key"]=1
			if [ -n "${GRANDFATHERED[$key]+x}" ]; then
				:
			else
				new_holdouts+=("$key")
			fi
			;;
	esac
done < "$RESULTS_FILE"

# Stale baseline entries: listed but the handler is no longer a
# holdout -- either bracketed (graduated, the success case) or the
# struct was removed/refactored.  Advisory, not fatal: someone may
# have hardened a handler in the same commit they ran the check, and
# pruning the baseline in a separate commit is fine.  The point is
# to surface the cleanup so the baseline shrinks instead of bit-rotting.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_HOLDOUT[$entry]+x}" ]; then
		stale_baseline+=("$entry")
	fi
done

if [ "${#new_holdouts[@]}" -gt 0 ]; then
	{
		echo "  ${#new_holdouts[@]} sanitise handler(s) stamp _POST_STATE_MAGIC but never wire snap into the ownership table:"
		for e in "${new_holdouts[@]}"; do echo "    $e"; done
		echo "  fix: replace 'rec->post_state = (unsigned long) snap;' with"
		echo "       'post_state_install(rec, snap);' (see syscalls/newstat.c for the helper form,"
		echo "       syscalls/execve.c for the equivalent hand-rolled rec->post_state + post_state_register pair),"
		echo "       and gate the .post handler's deref through post_state_claim_owned()."
		echo "       OR (only if hardening is deferred) add the entry to"
		echo "       scripts/check-static/post-state-ownership.baseline"
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer match a holdout (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_holdouts[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_holdouts[@]} unbracketed magic-only post_state handler(s)"
	exit 1
fi

baseline_size=${#GRANDFATHERED[@]}
total=${#SEEN_ANY[@]}
bracketed=$((total - baseline_size))
echo "PASS: $NAME (handlers=$total, bracketed=$bracketed, grandfathered=$baseline_size)"
exit 0
