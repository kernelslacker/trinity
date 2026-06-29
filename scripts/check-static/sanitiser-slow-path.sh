#!/bin/bash
#
# sanitiser-slow-path: forbid hot-path slow-syscall callsites in the
# sanitiser / argument-generation source set.
#
# Argument generation runs once per fuzzed syscall in the inner loop;
# the sanitiser surface that feeds it is expected to operate on cached
# state only.  Reaching for /proc/self/maps, fopen()/getline(), or a
# mincore()/mprotect() probe in that path violates the shape -- a
# single syscall here costs more than the entire rest of the
# arg-build, and the lock / FILE state pulled in by stdio is shared
# with the parent in ways that have surprised us before.
#
# The check is scoped to the files that participate in per-syscall
# argument generation; everything else (parent loop, stats, init,
# fuzz-control plumbing) is allowed to touch /proc.  In-scope files
# are bound explicitly in FILES below so the scope cannot widen by
# accident.
#
# Pre-existing offenders are baselined in sanitiser-slow-path.baseline
# (one `path:line:pattern` per line).  New offenders, or stale
# baseline entries, fail the check.  The baseline shrinks over time;
# it never grows.
#
# Suppress an individual call site with `/* check-static: slow-ok */`
# on the same line or the line immediately above the call.  Use the
# marker only when the cost is genuinely budgeted (e.g. a one-shot
# init path that snuck into a scoped file); otherwise hoist the slow
# call out of the hot path.

set -u

NAME="sanitiser-slow-path"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/sanitiser-slow-path.baseline"

# Explicit file list: the sanitiser / arg-generation surface.  Bound
# here rather than discovered so adding a new source file to this set
# is a deliberate edit.
FILES=(
	rand/interesting-numbers.c
	rand/mutate.c
	rand/random-address.c
	rand/random.c
	rand/random-length.c
	rand/random-page.c
	rand/rand-warn.c
	rand/seed.c
	rand/text-payloads.c
	generate-args.c
	random-syscall.c
	arg_coupling.c
	mutate.c
	struct_catalog.c
	struct_catalog/sctp.c
	struct_catalog/sockaddr.c
	struct_catalog/bpf.c
	struct_catalog/quota.c
	struct_catalog/time.c
	struct_catalog/perf.c
	struct_catalog/landlock.c
	arg-decoder.c
	lib/cmsg_build.c
	utils.c
)

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

current_tmp="$(mktemp)"
baseline_tmp="$(mktemp)"
trap 'rm -f "$current_tmp" "$baseline_tmp"' EXIT

# Per-file scan.  awk strips comments (block + line) and ordinary
# double-quoted string literals, then matches each forbidden pattern
# on a word boundary so identifiers that merely embed the name
# (openat, log_mprotect_failure, ...) do not trigger.  The `open(`
# pattern keeps the string literal in play so the "/proc-only" arm
# can fire; everything else matches against the string-stripped form
# so call names quoted inside log strings (outputerr("mprotect(...)"))
# are ignored.  Allowlist marker `/* check-static: slow-ok */` is
# honoured on the same line or the line immediately above.
for f in "${FILES[@]}"; do
	[ -f "$f" ] || continue
	awk -v file="$f" '
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
	function strip_strings(s) {
		gsub(/"[^"]*"/, "\"\"", s)
		return s
	}
	function emit(pat) {
		print file ":" NR ":" pat
	}
	BEGIN { in_block = 0; prev_raw = "" }
	{
		raw = $0
		code_str = strip_comments(raw)
		code = strip_strings(code_str)

		allow = 0
		if (raw ~ /check-static:[[:space:]]*slow-ok/) allow = 1
		else if (prev_raw ~ /check-static:[[:space:]]*slow-ok/) allow = 1

		if (!allow) {
			# open( with first arg starting "/proc -- needs the
			# string preserved, so match against code_str.
			if (match(code_str, /(^|[^A-Za-z0-9_])open[[:space:]]*\([[:space:]]*"\/proc/))
				emit("open(/proc")
			if (match(code, /(^|[^A-Za-z0-9_])fopen[[:space:]]*\(/))
				emit("fopen")
			if (match(code, /(^|[^A-Za-z0-9_])getline[[:space:]]*\(/))
				emit("getline")
			if (match(code, /(^|[^A-Za-z0-9_])mincore[[:space:]]*\(/))
				emit("mincore")
			if (match(code, /(^|[^A-Za-z0-9_])mprotect[[:space:]]*\(/))
				emit("mprotect")
		}

		prev_raw = raw
	}
	' "$f"
done | sort -u > "$current_tmp"

if [ -r "$BASELINE" ]; then
	sed -e 's/#.*$//' -e 's/[[:space:]]\+$//' "$BASELINE" \
		| grep -v '^[[:space:]]*$' \
		| sort -u > "$baseline_tmp"
else
	: > "$baseline_tmp"
fi

new_violators="$(comm -23 "$current_tmp" "$baseline_tmp")"
stale_baseline="$(comm -13 "$current_tmp" "$baseline_tmp")"

fail=0

if [ -n "$new_violators" ]; then
	fail=1
	{
		echo "  $NAME: new slow-path call(s) in sanitiser / arg-gen scope:"
		echo "$new_violators" | sed 's/^/    /'
		echo "  fix: hoist the call to a one-shot init / parent path and"
		echo "       cache the result; the inner arg-gen loop must read"
		echo "       cached state only.  See heap_bounds_init() in utils.c"
		echo "       for the canonical 'read /proc once, query later' shape."
		echo "       If the cost is genuinely budgeted, mark the line with"
		echo "       /* check-static: slow-ok */ on the same or preceding"
		echo "       line, or add the entry to"
		echo "       scripts/check-static/sanitiser-slow-path.baseline."
	} >&2
fi

if [ -n "$stale_baseline" ]; then
	fail=1
	{
		echo "  $NAME: baseline entry/entries no longer match a call site -"
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
