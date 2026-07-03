#!/bin/bash
#
# track-shared-region-pairing: every track_shared_region() must have a
# matching untrack_shared_region() on every exit path that can free or
# recycle the backing mapping.  A leak here drifts the shared-region
# bookkeeping silently -- range_overlaps_shared() starts answering on
# entries whose VAs the kernel has already recycled, masking real
# sanitiser hits and skewing mm-syscall coverage.
#
# Pragmatic single-function-body scan: this is not a real CFG.  awk
# walks each .c file, isolates the body of every function that mentions
# track_shared_region(, and counts:
#
#   T  = number of track_shared_region(   calls.
#   U  = number of untrack_shared_region( calls.
#   E  = number of goto-to-cleanup-label statements (`goto err*`,
#        `goto out*`, `goto cleanup*`, `goto fail*`) that appear AFTER
#        the LAST track_shared_region( in the function body.
#
# "After the last track" rather than "after the first" is the
# helper-aware refinement: a function that tracks once and then hands
# the registered region off to a destructor (mmap_fd, phdr_callback,
# kcov_init_child) typically has no cleanup-goto after the final track
# because the destructor owns the untrack.  A function that tracks and
# then can goto a cleanup label that munmaps the region without
# untracking IS the leak shape this check catches.
#
# `return` statements are deliberately NOT counted.  Every function has
# a normal-completion return; counting it would false-positive on every
# handoff site.  Real leaks in this codebase show up as goto-to-error-
# label paths whose label body munmaps the tracked region.
#
# Two FAIL conditions, kept verbatim from the spec:
#   (a) T > 0 && U == 0 && E > 0
#   (b) T > U && E >= (T - U)
#
# Allow-list:
#   - Function names matching destroy / destructor / release / cleanup
#     (per-type destructors only ever untrack -- they don't track).
#   - utils/shared_mem.c (defines track_shared_region /
#     untrack_shared_region themselves).
#
# Auto-discovered by scripts/check-static.sh -- no registration needed.

set -u

NAME="track-shared-region-pairing"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# Build the candidate file list: every .c file that mentions
# track_shared_region(.  utils/shared_mem.c is the home of the
# function definitions themselves and is excluded.
mapfile -t SRCFILES < <(grep -lE '\<track_shared_region[[:space:]]*\(' \
		--include='*.c' -r . 2>/dev/null \
	| grep -vE '(^|/)utils/shared_mem\.c$' \
	| sort)

if [ "${#SRCFILES[@]}" -eq 0 ]; then
	echo "PASS: $NAME (no track_shared_region call sites)"
	exit 0
fi

# awk walks each file once, isolates each function body via brace
# balance, and emits a FAIL line per offending function.
awk '
function reset_fn() {
	in_fn = 0
	depth = 0
	fn_name = ""
	fn_start_line = 0
	T = 0
	U = 0
	E = 0
	saw_any_track = 0
}

function reset_file() {
	reset_fn()
	candidate_name = ""
	candidate_line = 0
}

# Pull the function name out of a signature line.  Take the LAST
# identifier before the first ( on the line.  Filter the common
# control-flow / declaration keywords so a stray `if (foo) { ... }`
# at column 0 (inside a macro body, say) does not get mistaken for
# the start of a function called "if".
function extract_funcname(line,    work, name) {
	work = line
	if (match(work, /[(]/))
		work = substr(work, 1, RSTART - 1)
	if (match(work, /[{]/))
		work = substr(work, 1, RSTART - 1)
	name = ""
	while (match(work, /[a-zA-Z_][a-zA-Z_0-9]*/)) {
		name = substr(work, RSTART, RLENGTH)
		work = substr(work, RSTART + RLENGTH)
	}
	if (name == "if" || name == "for" || name == "while" ||
	    name == "switch" || name == "do" || name == "case" ||
	    name == "goto" || name == "return" || name == "sizeof" ||
	    name == "static" || name == "extern" || name == "inline" ||
	    name == "typedef" || name == "struct" || name == "union" ||
	    name == "enum")
		return ""
	return name
}

function is_allowlisted_name(name) {
	if (name == "")
		return 1
	if (name ~ /destroy/) return 1
	if (name ~ /destructor/) return 1
	if (name ~ /release/) return 1
	if (name ~ /cleanup/) return 1
	return 0
}

function check_and_emit(    fpath) {
	if (T == 0)
		return
	if (is_allowlisted_name(fn_name))
		return

	fpath = fn_file
	sub(/^\.\//, "", fpath)

	# (a) tracks but never untracks, with at least one cleanup goto
	#     after the last track.
	if (T > 0 && U == 0 && E > 0) {
		printf "FAIL: track-shared-region-pairing: %s:%s: track=%d untrack=%d early-exit=%d (suspected leak)\n",
			fpath, fn_name, T, U, E
		return
	}
	# (b) more tracks than untracks AND enough cleanup-gotos after
	#     the last track to leave at least one unmatched.
	if (T > U && E >= (T - U)) {
		printf "FAIL: track-shared-region-pairing: %s:%s: track=%d untrack=%d early-exit=%d (suspected leak)\n",
			fpath, fn_name, T, U, E
	}
}

# Process one source line for tracks/untracks/cleanup-gotos.  E is the
# running count of cleanup-gotos seen SINCE the last track call -- a
# new track() reset E to 0 below.  At flush time E holds gotos after
# the LAST track.
function process_line(line,    tmp, c) {
	# Skip pure comment / continuation lines so banners that quote
	# the function names do not skew the counts.
	if (line ~ /^[[:space:]]*\*/) return
	if (line ~ /^[[:space:]]*\/\*/) return
	if (line ~ /^[[:space:]]*\/\//) return

	# Drop line-comment tail before pattern matching so a trailing
	# `// foo goto err` does not register.
	sub(/\/\/.*$/, "", line)

	# track_shared_region(.  The leading [^a-zA-Z0-9_] guard ensures
	# untrack_shared_region does not match as a track.  A new track
	# resets the cleanup-goto counter so E ends up holding the count
	# AFTER the most recent track.
	tmp = " " line
	c = gsub(/[^a-zA-Z0-9_]track_shared_region[[:space:]]*\(/, "&", tmp)
	if (c > 0) {
		T += c
		saw_any_track = 1
		E = 0
	}

	# untrack_shared_region(
	tmp = " " line
	c = gsub(/[^a-zA-Z0-9_]untrack_shared_region[[:space:]]*\(/, "&", tmp)
	U += c

	# Only count cleanup-gotos that follow a track call.
	if (!saw_any_track)
		return

	# goto err* / goto out* / goto cleanup* / goto fail*
	if (line ~ /(^|[^a-zA-Z0-9_])goto[[:space:]]+(err|out|cleanup|fail)/)
		E++
}

BEGIN { reset_file() }

FNR == 1 {
	reset_file()
	fn_file = FILENAME
}

{
	raw = $0
	line_no_lc = raw
	sub(/\/\/.*$/, "", line_no_lc)

	# Brace deltas.  Strings containing { } are rare in trinity and
	# not worth the lexer cost; the existing post-double-publish.sh
	# check accepts the same tradeoff.
	n_open = gsub(/\{/, "{", line_no_lc)
	n_close = gsub(/\}/, "}", line_no_lc)
	delta = n_open - n_close

	if (!in_fn) {
		# Buffer the latest function-signature candidate.
		if (raw ~ /^[a-zA-Z_]/ && raw ~ /\(/) {
			name = extract_funcname(raw)
			if (name != "") {
				candidate_name = name
				candidate_line = FNR
			}
		}

		if (delta > 0 && candidate_name != "") {
			in_fn = 1
			fn_name = candidate_name
			fn_start_line = candidate_line
			depth = delta
			T = 0; U = 0; E = 0
			saw_any_track = 0
			process_line(raw)
			if (depth == 0) {
				check_and_emit()
				reset_fn()
				candidate_name = ""
			}
		}
		# delta > 0 without a candidate is a struct / enum /
		# union / initialiser at file scope -- ignore.
		next
	}

	# Inside a function body.
	depth += delta
	process_line(raw)
	if (depth <= 0) {
		check_and_emit()
		reset_fn()
		candidate_name = ""
	}
}

END {
	if (in_fn)
		check_and_emit()
}
' "${SRCFILES[@]}" > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	cat "$hits_tmp" >&2
	{
		echo "  $NAME: $n function(s) with suspected track/untrack leak."
		echo "  fix: every track_shared_region() needs a matching"
		echo "       untrack_shared_region() before the function leaves"
		echo "       on any path.  The error-cleanup label that munmaps"
		echo "       the tracked region must call untrack_shared_region"
		echo "       BEFORE munmap.  Mirror the open_io_uring_fd_config"
		echo "       and create_one_vcpu error-cleanup shapes."
	} >&2
	echo "FAIL: $NAME: $n suspected leak(s)"
	exit 1
fi

echo "PASS: $NAME"
exit 0
