#!/bin/bash
#
# post-state-deref: every `.post` handler that reads rec->post_state
# into a local pointer and then dereferences it must first gate the
# deref with looks_like_corrupted_ptr() or a *_POST_STATE_MAGIC cookie
# compare.
#
# Sibling check to post-state-magic.sh: that one validates the STRUCT
# definition (every post_state struct must carry a magic cookie); this
# one validates the USE SITE (the handler must actually consult the
# cookie / heap-shape gate before chasing the pointer).
#
# The bug class this catches is the io_submit post_state deref
# (fixed in f9a2e3f2cc06): post_io_submit() snapshotted iocbpp into
# rec->post_state, NULL-checked the snapshot, and then walked iocbpp[i]
# straight through.  A sibling-syscall scribble of rec->post_state with
# a heap-shaped but foreign pointer would slip past the NULL gate and
# drive a child SIGSEGV that surfaced as a false-positive trinity bug.
# The sibling post_io_setup() handler had it right -- gate with
# looks_like_corrupted_ptr() before dereferencing.
#
# Heuristic: for each function named on a `.post = HANDLER,` line in
# syscalls/, parse the function body.  Treat any local pointer assigned
# from rec->post_state as tainted; if the body subsequently dereferences
# that local (via `->`, `[`, or unary `*`) without containing either
# `looks_like_corrupted_ptr(` or a `*_POST_STATE_MAGIC` token in the
# same function, the handler is flagged.
#
# A baseline of grandfathered handlers may live alongside this script as
# post-state-deref.baseline (one `file:funcname` per line).  The
# baseline should shrink over time, never grow.

set -u

NAME="post-state-deref"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/post-state-deref.baseline"

declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

# Collect every post-handler symbol referenced from any
# `.post = NAME,` assignment in syscalls/.  The handler definition
# may live in the same file or a sibling, so we treat the set as a
# global symbol table and re-scan every syscalls/*.c for definitions.
POST_NAMES_FILE="$(mktemp)"
trap 'rm -f "$POST_NAMES_FILE" "$RESULTS_FILE" 2>/dev/null' EXIT
RESULTS_FILE="$(mktemp)"

grep -hE '^[[:space:]]*\.post[[:space:]]*=' "$ROOT"/syscalls/*.c \
	| sed -e 's/.*\.post[[:space:]]*=[[:space:]]*//' \
	      -e 's/[[:space:],].*//' \
	| sort -u > "$POST_NAMES_FILE"

# Per-file scan.  awk extracts each function whose name is in the
# post-handler set, then runs the deref/guard heuristic on its body.
while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"
	awk -v file="$rel" -v posts_file="$POST_NAMES_FILE" '
	BEGIN {
		while ((getline n < posts_file) > 0)
			if (n != "") is_post[n] = 1
		close(posts_file)
		state = 0       # 0 = scanning, 1 = inside post handler body
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
	function strip_comments(s) {
		# Crude but adequate for single-line scanning of post handlers.
		sub(/\/\/.*$/, "", s)
		gsub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, " ", s)
		return s
	}
	function reset_state() {
		cur_fname = ""
		delete tainted
		cur_deref = 0
		cur_guard = 0
		cur_reads = 0
	}
	function analyze_line(line,    v, pat, m, code) {
		code = strip_comments(line)

		# Guard tokens.  Either is sufficient; we trust the author to
		# place the check before the deref it gates.
		if (code ~ /looks_like_corrupted_ptr[[:space:]]*\(/) cur_guard = 1
		if (code ~ /_POST_STATE_MAGIC/) cur_guard = 1

		# Direct deref of rec->post_state without going through a local
		# -- a handler chasing rec->post_state-> straight through is the
		# bug shape we are explicitly looking for.
		if (code ~ /rec->post_state[[:space:]]*->/) cur_deref = 1
		if (code ~ /rec->post_state[[:space:]]*\[/) cur_deref = 1

		# Assignment from rec->post_state to a local pointer.  Two
		# spellings appear in the tree:
		#     var = (TYPE *) rec->post_state;
		#     var = rec->post_state;
		# In either case the LHS identifier becomes tainted.
		if (match(code, /([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*\([^()]*\*[[:space:]]*\)[[:space:]]*rec->post_state/, m)) {
			tainted[m[1]] = 1
			cur_reads = 1
		} else if (match(code, /([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*rec->post_state([^A-Za-z0-9_]|$)/, m)) {
			tainted[m[1]] = 1
			cur_reads = 1
		}

		# Deref of any tainted local.
		for (v in tainted) {
			pat = "(^|[^A-Za-z0-9_])" v "[[:space:]]*->"
			if (code ~ pat) cur_deref = 1
			pat = "(^|[^A-Za-z0-9_])" v "[[:space:]]*\\["
			if (code ~ pat) cur_deref = 1
			pat = "\\*[[:space:]]*" v "([^A-Za-z0-9_]|$)"
			if (code ~ pat) cur_deref = 1
		}
	}
	{
		if (state == 0) {
			# Function-definition opener: a line beginning with `static`
			# that ends with `(` introducing the parameter list, with
			# the function name as the last identifier before the paren.
			if (match($0, /^[[:space:]]*static[[:space:]].*[[:space:]\*]([A-Za-z_][A-Za-z0-9_]+)[[:space:]]*\(/, m)) {
				fname = m[1]
				if (fname in is_post) {
					reset_state()
					cur_fname = fname
					state = 1
					depth = 0
					# Fall through to scan this line for `{` and content.
				}
			}
		}
		if (state == 1) {
			analyze_line($0)
			depth += brace_delta($0)
			if (depth <= 0 && $0 ~ /\}/) {
				# Body finished.  Decide.
				if (cur_reads && cur_deref && !cur_guard) {
					print "VIOLATION " file ":" cur_fname
				}
				if (cur_reads) {
					print "SEEN " file ":" cur_fname
				}
				state = 0
				depth = 0
				reset_state()
			}
		}
	}
	' "$srcfile"
done < <(find "$ROOT/syscalls" -name '*.c' -print | sort) > "$RESULTS_FILE"

new_unbaselined=()
declare -A SEEN_KEY=()

while IFS=' ' read -r kind key; do
	case "$kind" in
		SEEN)
			SEEN_KEY["$key"]=1
			;;
		VIOLATION)
			if [ -n "${GRANDFATHERED[$key]+x}" ]; then
				:
			else
				new_unbaselined+=("$key")
			fi
			;;
	esac
done < "$RESULTS_FILE"

# Stale baseline entries: still listed but the handler no longer reads
# post_state at all (was hardened or removed).  Advisory, not fatal.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_KEY[$entry]+x}" ]; then
		stale_baseline+=("$entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} post handler(s) deref rec->post_state without a guard:"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo "  fix: gate the deref with looks_like_corrupted_ptr(rec, p)"
		echo "       and (where the struct carries one) a *_POST_STATE_MAGIC compare,"
		echo "       OR add the entry to scripts/check-static/post-state-deref.baseline"
		echo "       if hardening is deferred to a follow-up commit."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer match a"
		echo "        post handler that reads post_state (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} unguarded post_state deref(s)"
	exit 1
fi

baseline_size=${#GRANDFATHERED[@]}
total=${#SEEN_KEY[@]}
hardened=$((total - baseline_size))
echo "PASS: $NAME (handlers=$total, hardened=$hardened, grandfathered=$baseline_size)"
exit 0
