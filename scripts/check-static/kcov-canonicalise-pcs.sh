#!/bin/bash
#
# kcov-canonicalise-pcs: every PC hashed into kcov_shm->bucket_seen[]
# or kcov_shm->transition_seen[] must first be canonicalised against
# the runtime KASLR base by kcov_canon_pc, so the slot index for a
# given instruction is invariant across reboots of the same kernel
# build.
#
# Without canonicalisation the slot index for a given instruction
# shifts on every KASLR reroll, silently aliasing the cached bitmap
# across reboots that the kallsyms fingerprint (deliberately KASLR-
# invariant) already considers identical.  See the kcov_canon_pc /
# pc_canon_to_edge / KCOV_BITMAP_FILE_VERSION comments in kcov.c for
# the design.
#
# The PC -> edge-index hash is pc_canon_to_edge() and the
# (prev, cur) -> transition-slot hash is pair_to_transition(); both
# take already-canonicalised inputs so the caller can canonicalise
# once per PC at the head of the trace walk and feed the same value
# into both without paying kcov_canon_pc twice.  This check enforces
# three invariants:
#
#   1. kcov_canon_pc itself subtracts kcov_kaslr_base.  Without this
#      the helper degrades to identity and the canonicalisation claim
#      is silently false.
#   2. pc_canon_to_edge does NOT invoke kcov_canon_pc.  A canon-in
#      helper that re-canonicalises would double-subtract the base on
#      callers that have already canonicalised, and would let a caller
#      forget to canonicalise yet still appear correct because the
#      inner call covered for them.
#   3. Every function in kcov.c that calls pc_canon_to_edge also calls
#      kcov_canon_pc somewhere in the same body.  This is the static
#      stand-in for "pc_canon_to_edge is never reached with a raw PC":
#      the only way to produce a canonical PC in this codebase is to
#      route a raw PC through kcov_canon_pc, so an enclosing function
#      that reaches the hash helper without ever calling the
#      canonicaliser cannot have a canonicalised input.

set -u

NAME="kcov-canonicalise-pcs"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

if [ ! -f kcov.c ]; then
	echo "FAIL: $NAME: kcov.c not found at $ROOT"
	exit 1
fi

# 1. kcov_canon_pc body must subtract kcov_kaslr_base.
canon_body="$(awk '
	/^static inline unsigned long kcov_canon_pc\(/ { in_body = 1 }
	in_body { print }
	in_body && /^}/ { exit }
' kcov.c)"

if [ -z "$canon_body" ]; then
	echo "FAIL: $NAME: kcov_canon_pc() definition not found in kcov.c"
	exit 1
fi

if ! grep -q 'kcov_kaslr_base' <<< "$canon_body"; then
	{
		echo "  $NAME: kcov_canon_pc() does not reference kcov_kaslr_base:"
		echo "$canon_body" | sed 's/^/    /'
		echo "  fix: kcov_canon_pc() must subtract kcov_kaslr_base from"
		echo "       its argument; without that the slot index is the"
		echo "       raw PC again and cross-reboot warm-start aliases."
	} >&2
	echo "FAIL: $NAME: kcov_canon_pc() missing kcov_kaslr_base subtraction"
	exit 1
fi

# 2. pc_canon_to_edge body must NOT invoke kcov_canon_pc.
edge_body="$(awk '
	/^static inline unsigned int pc_canon_to_edge\(/ { in_body = 1 }
	in_body { print }
	in_body && /^}/ { exit }
' kcov.c)"

if [ -z "$edge_body" ]; then
	echo "FAIL: $NAME: pc_canon_to_edge() definition not found in kcov.c"
	exit 1
fi

if grep -q 'kcov_canon_pc' <<< "$edge_body"; then
	{
		echo "  $NAME: pc_canon_to_edge() invokes kcov_canon_pc:"
		echo "$edge_body" | sed 's/^/    /'
		echo "  fix: pc_canon_to_edge() takes an already-canonicalised PC."
		echo "       Calling kcov_canon_pc inside it would double-subtract"
		echo "       the KASLR base on the trace walk's per-PC canonicalisation"
		echo "       and silently mask any caller that forgets to canonicalise."
	} >&2
	echo "FAIL: $NAME: pc_canon_to_edge() must not re-canonicalise"
	exit 1
fi

# 3. Every function in kcov.c that calls pc_canon_to_edge() must also
#    call kcov_canon_pc() somewhere in the same body.  Walks kcov.c
#    function-by-function: a function header is a line that starts at
#    column 0 with a return type and a paren, and the matching close
#    brace also starts at column 0.  Trinity follows that style
#    throughout kcov.c so the heuristic is reliable.
missing="$(awk '
	/^[A-Za-z_][A-Za-z0-9_ *]*[A-Za-z0-9_*]\(/ && !in_body {
		match($0, /[A-Za-z_][A-Za-z0-9_]*\(/)
		name = substr($0, RSTART, RLENGTH - 1)
		header_line = NR
		want = 1
	}
	want && /\{[[:space:]]*$/ && !in_body {
		in_body = 1
		want = 0
		has_canon = 0
		has_edge = 0
		next
	}
	in_body {
		if (index($0, "kcov_canon_pc") > 0) has_canon = 1
		if (index($0, "pc_canon_to_edge") > 0) has_edge = 1
	}
	in_body && /^}/ {
		if (has_edge && !has_canon)
			printf("%s:%d: %s\n", FILENAME, header_line, name)
		in_body = 0
		want = 0
	}
' kcov.c)"

if [ -n "$missing" ]; then
	{
		echo "  $NAME: function(s) call pc_canon_to_edge but never kcov_canon_pc:"
		echo "$missing" | sed 's/^/    /'
		echo "  fix: pc_canon_to_edge takes an already-canonicalised PC."
		echo "       The enclosing function must have routed the raw PC"
		echo "       through kcov_canon_pc before reaching the hash."
	} >&2
	echo "FAIL: $NAME: pc_canon_to_edge reached without kcov_canon_pc"
	exit 1
fi

echo "PASS: $NAME: pc_canon_to_edge fed only by kcov_canon_pc'd PCs"
exit 0
