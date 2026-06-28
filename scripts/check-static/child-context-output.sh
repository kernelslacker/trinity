#!/bin/bash
#
# child-context-output: flag output() / outputerr() / outputstd()
# calls reached from child-context code, where they vanish silently.
#
# init_child() (child.c) dup2's /dev/null over stdin/stdout/stderr in
# every child before any syscall fuzzing starts.  output(),
# outputerr() and outputstd() write to the inherited stdio streams, so
# any call reached from child-side code drops on the floor and the
# diagnostic the author thought they were emitting is invisible to the
# operator -- the "missing crash log" bug class.
#
# Two child-side surfaces are covered:
#
#   (1) .post handlers.  syscallentry.post runs in the child between
#       the syscall returning and the record being released.  Any
#       output() in the .post handler -- or in a helper the handler
#       calls within the same translation unit -- is silenced.
#
#   (2) childops.  childops/*.c always runs child-side (the dispatch
#       walks the array from the child loop).  Every output() call in
#       any function inside a childops/*.c file is silenced.
#
# Heuristic, not AST:
#
#   - Discover .post handler names from `.post = NAME,` assignments in
#     syscalls/*.c.
#   - Per syscalls/*.c file, walk the file once: for every function
#     definition record its name, the set of identifiers it calls, and
#     the file:line of every output()/outputerr()/outputstd() inside
#     it.  Compute the transitive closure (within the file) of
#     functions reachable from any .post handler and emit hits inside
#     that closure.
#
#   - Per childops/*.c file, emit every output()/outputerr()/
#     outputstd() hit inside any function body.  (Top-of-file enum
#     initialisers etc. cannot host a call expression, so the function-
#     body gate is implicit.)
#
# Cross-file call edges are deliberately NOT chased: the audit budget
# is grep-shaped, and the false-negative this admits is a follow-up
# patch's problem.  Helpers that should always be silent-safe can move
# their helper-callees into the same file or get baselined.
#
# Per-callsite allowlist: add the comment
#     /* check-static: child-output-ok */
# on the same line as the call or on the line immediately above.
# Intended use is the rare debug-only callsite where the author has
# manually removed the init_child redirect while bisecting.
#
# Baseline: scripts/check-static/child-context-output.baseline lists
# every grandfathered offender as `file:funcname` -- keyed by the
# function, not the line, so a callsite drifting lines never churns
# the baseline (the grandfathered unit is the function).  This check
# will fire on a large existing surface (every existing callsite is
# baselined); the list should shrink over time, never grow.

set -u

NAME="child-context-output"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/child-context-output.baseline"

declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

POSTS_FILE="$(mktemp)"
RAW_FILE="$(mktemp)"
HITS_FILE="$(mktemp)"
trap 'rm -f "$POSTS_FILE" "$RAW_FILE" "$HITS_FILE"' EXIT

# Collect every .post handler name from any syscallentry table.
grep -hE '^[[:space:]]*\.post[[:space:]]*=' "$ROOT"/syscalls/*.c \
	| sed -e 's/.*\.post[[:space:]]*=[[:space:]]*//' \
	      -e 's/[[:space:],].*//' \
	| sort -u > "$POSTS_FILE"

# Per-file scanner.  Modes:
#   mode=post     -- emit DEF / CALL / HIT records, post-process to
#                    filter by reachability from .post handlers.
#   mode=childop  -- emit HIT records directly (every body counts).
scan_file() {
	local srcfile="$1" rel="$2" mode="$3"
	awk -v file="$rel" -v posts_file="$POSTS_FILE" -v mode="$mode" '
	BEGIN {
		in_block = 0
		in_func = 0
		depth = 0
		cur_fn = ""
		pending = ""
		prev_marker = 0
		marker = "check-static: child-output-ok"
		if (mode == "post") {
			while ((getline n < posts_file) > 0)
				if (n != "") is_post[n] = 1
			close(posts_file)
		}
	}
	function strip_comments(s,    idx, tail, cidx) {
		if (in_block) {
			idx = index(s, "*/")
			if (idx == 0) return ""
			s = substr(s, idx + 2)
			in_block = 0
		}
		while ((idx = index(s, "/*")) > 0) {
			tail = substr(s, idx + 2)
			cidx = index(tail, "*/")
			if (cidx == 0) {
				in_block = 1
				s = substr(s, 1, idx - 1)
				break
			}
			s = substr(s, 1, idx - 1) " " substr(tail, cidx + 2)
		}
		sub(/\/\/.*$/, "", s)
		return s
	}
	function count_char(s, ch,    i, n) {
		n = 0
		for (i = 1; i <= length(s); i++)
			if (substr(s, i, 1) == ch) n++
		return n
	}
	function rtrim(s) {
		sub(/[[:space:]]+$/, "", s)
		return s
	}
	function record_calls(code, fn,    rest, m, callee) {
		# Record every IDENT( occurrence in the code as a potential
		# callee of fn.  Keywords filtered.  Over-collection is fine
		# -- reachability post-processing only follows names that
		# match a recorded DEF.
		rest = code
		while (match(rest, /([A-Za-z_][A-Za-z0-9_]+)[[:space:]]*\(/, m)) {
			callee = m[1]
			if (callee != "if" && callee != "for" && \
			    callee != "while" && callee != "switch" && \
			    callee != "sizeof" && callee != "return" && \
			    callee != "do" && callee != "case") {
				printf "CALL|%s|%s|%s\n", file, fn, callee
			}
			rest = substr(rest, RSTART + RLENGTH)
		}
	}
	function record_hits(raw, code, fn, this_marker, prev_marker,    \
			     rest, m, allow, kind) {
		allow = (this_marker || prev_marker)
		rest = code
		while (match(rest, /(^|[^A-Za-z0-9_])(outputerr|outputstd|output)[[:space:]]*\(/, m)) {
			kind = substr(rest, RSTART, RLENGTH)
			sub(/^[^A-Za-z]/, "", kind)
			sub(/[[:space:]]*\(.*/, "", kind)
			if (!allow) {
				printf "HIT|%s|%d|%s|%s\n", \
					file, NR, fn, kind
			}
			rest = substr(rest, RSTART + RLENGTH)
		}
	}
	{
		raw = $0
		this_marker = (index(raw, marker) > 0) ? 1 : 0
		code = strip_comments(raw)
		opens = count_char(code, "{")
		closes = count_char(code, "}")

		if (in_func == 0) {
			# Candidate function-definition signature line:
			# column 0, contains `IDENT(`, does not end with
			# `;` or `=` (which would be a prototype or
			# definition-of-data).
			if (match(raw, /^[[:space:]]*(static[[:space:]]+)?[A-Za-z_][A-Za-z0-9_[:space:]\*]*[[:space:]\*]([A-Za-z_][A-Za-z0-9_]+)[[:space:]]*\(/, m)) {
				trimmed_end = rtrim(code)
				last = substr(trimmed_end, length(trimmed_end), 1)
				if (last == ")" || last == "," || last == "{" || last == "(") {
					pending = m[2]
				}
			}
			if (pending != "" && opens > 0) {
				cur_fn = pending
				pending = ""
				in_func = 1
				depth = opens - closes
				printf "DEF|%s|%s\n", file, cur_fn
				record_calls(code, cur_fn)
				record_hits(raw, code, cur_fn, this_marker, prev_marker)
				if (depth <= 0) {
					in_func = 0
					cur_fn = ""
					depth = 0
				}
			}
		} else {
			record_calls(code, cur_fn)
			record_hits(raw, code, cur_fn, this_marker, prev_marker)
			depth += opens - closes
			if (depth <= 0) {
				in_func = 0
				cur_fn = ""
				depth = 0
			}
		}
		prev_marker = this_marker
	}
	' "$srcfile"
}

# Pass 1: syscalls/*.c.  Collect raw DEF/CALL/HIT records.
while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"
	scan_file "$srcfile" "$rel" post
done < <(find "$ROOT/syscalls" -name '*.c' | sort) > "$RAW_FILE"

# Post-process syscalls records: compute per-file reachability set
# starting from .post handler names, then emit hits inside the set.
awk -v posts_file="$POSTS_FILE" '
BEGIN {
	while ((getline n < posts_file) > 0)
		if (n != "") is_post[n] = 1
	close(posts_file)
}
{
	split($0, a, "|")
	kind = a[1]
	if (kind == "DEF") {
		# Track that file/fn pair exists.
		def[a[2] "|" a[3]] = 1
	} else if (kind == "CALL") {
		# a[2]=file a[3]=caller a[4]=callee
		key = a[2] "|" a[3]
		edges[key] = (edges[key] == "") ? a[4] : edges[key] " " a[4]
		} else if (kind == "HIT") {
			# a[2]=file a[4]=fn.  Record func-level presence only --
			# the baseline is keyed file:funcname, so the line (a[3])
			# and kind (a[5]) are not part of the key.
			hits[a[2] "|" a[4]] = 1
		}
}
END {
	# Seed reachable[] with every .post handler that has a DEF in
	# any file.
	for (d in def) {
		split(d, p, "|")
		if (p[2] in is_post) reachable[d] = 1
	}
	# Iterate to fixed point per file (edges map is keyed by
	# file|caller, so transitive closure stays within the file).
	changed = 1
	while (changed) {
		changed = 0
		for (k in reachable) {
			if (k in edges) {
				split(k, p, "|")
				n = split(edges[k], cs, " ")
				for (i = 1; i <= n; i++) {
					target = p[1] "|" cs[i]
					if (target in def && !(target in reachable)) {
						reachable[target] = 1
						changed = 1
					}
				}
			}
		}
	}
	# Emit one entry per reachable function that has a hit. The
	# baseline is keyed file:funcname (NOT file:line): the
	# grandfathered unit is the function, so a callsite drifting
	# lines does not churn the baseline.
	for (k in reachable) {
		if (k in hits) {
			split(k, p, "|")
			printf "syscalls|%s:%s\n", p[1], p[2]
		}
	}
}
' "$RAW_FILE" > "$HITS_FILE"

# Pass 2: childops/*.c.  Every body counts; HIT records are emitted
# directly without reachability filtering.
while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"
	scan_file "$srcfile" "$rel" childop
done < <(find "$ROOT/childops" -name '*.c' | sort) \
		| awk -F'|' '$1=="HIT" { print "childops|" $2 ":" $4 }' \
	>> "$HITS_FILE"

# Classify hits against the baseline.
new_unbaselined=()
declare -A SEEN_KEY=()
syscalls_count=0
childops_count=0

while IFS='|' read -r bucket entry; do
	[ -z "$entry" ] && continue
	[ -n "${SEEN_KEY[$entry]+x}" ] && continue
	SEEN_KEY["$entry"]=1
	case "$bucket" in
		syscalls) syscalls_count=$((syscalls_count + 1)) ;;
		childops) childops_count=$((childops_count + 1)) ;;
	esac
	if [ -z "${GRANDFATHERED[$entry]+x}" ]; then
		new_unbaselined+=("$entry")
	fi
done < "$HITS_FILE"

stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_KEY[$entry]+x}" ]; then
		stale_baseline+=("$entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} child-context output()/outputerr()/outputstd() call(s):"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo "  fix: route the diagnostic through a parent-visible path"
		echo "       (defer via the record, surface from a parent-side"
		echo "       handler), suppress the callsite with"
		echo "       /* check-static: child-output-ok */, or add the"
		echo "       entry to scripts/check-static/child-context-output.baseline"
		echo "       if remediation is deferred to a follow-up commit."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer"
		echo "        match a live call site (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} unbaselined child-context output() call(s)"
	exit 1
fi

baseline_size=${#GRANDFATHERED[@]}
total=${#SEEN_KEY[@]}
echo "PASS: $NAME (total=$total syscalls=$syscalls_count childops=$childops_count baselined=$baseline_size)"
exit 0
