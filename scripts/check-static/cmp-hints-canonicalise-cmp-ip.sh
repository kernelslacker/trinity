#!/bin/bash
#
# cmp-hints-canonicalise-cmp-ip: every cmp_ip that enters the cmp-hints
# bloom or per-syscall pool (and, by extension, the persisted on-disk
# file) must first be canonicalised against the runtime KASLR base by
# kcov_canon_cmp_ip, so the (cmp_ip, value, size) keys are invariant
# across reboots of the same kernel build.
#
# Without canonicalisation the cmp_ip column of every pool entry shifts
# on every KASLR reroll, silently aliasing the warm-loaded pool against
# the live one even when the kallsyms fingerprint (deliberately KASLR-
# invariant) already considers the two kernels identical -- field-scoped
# scoring planned on top of cmp_ip then compounds the noise.  The
# canonicalisation companion to scripts/check-static/kcov-canonicalise-
# pcs.sh on the PC-coverage side.  This check enforces two invariants:
#
#   1. kcov_canon_cmp_ip itself subtracts kcov_kaslr_base.  Without this
#      the helper degrades to identity and the canonicalisation claim
#      is silently false (every cmp_ip enters the pool raw and survives
#      warm-load against a same-fingerprint kernel as a fresh alias).
#   2. Every function in cmp_hints.c that calls
#      cmp_hints_bloom_check_and_set OR pool_add_locked also calls
#      kcov_canon_cmp_ip somewhere in the same body.  This is the
#      static stand-in for "the bloom and the pool are never reached
#      with a raw cmp_ip": the only way to produce a canonical cmp_ip
#      in this codebase is to route a raw PC through kcov_canon_cmp_ip,
#      so an enclosing function that reaches either ingress without
#      ever calling the canonicaliser cannot have a canonicalised
#      input.  cmp_hints_flush_pending() is the one whitelisted
#      transitive caller: it takes its (ip, val, size) tuples from a
#      staging batch that cmp_hints_collect() populated with values
#      that ARE already canonical -- enforcing the rule on the leaf
#      site would force a redundant second canonicalisation on every
#      batched record.

set -u

NAME="cmp-hints-canonicalise-cmp-ip"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

if [ ! -f cmp_hints.c ]; then
	echo "FAIL: $NAME: cmp_hints.c not found at $ROOT"
	exit 1
fi
if [ ! -f kcov.c ]; then
	echo "FAIL: $NAME: kcov.c not found at $ROOT"
	exit 1
fi

# 1. kcov_canon_cmp_ip body must subtract kcov_kaslr_base.
canon_body="$(awk '
	/^unsigned long kcov_canon_cmp_ip\(/ { in_body = 1 }
	in_body { print }
	in_body && /^}/ { exit }
' kcov.c)"

if [ -z "$canon_body" ]; then
	echo "FAIL: $NAME: kcov_canon_cmp_ip() definition not found in kcov.c"
	exit 1
fi

if ! grep -q 'kcov_kaslr_base' <<< "$canon_body"; then
	{
		echo "  $NAME: kcov_canon_cmp_ip() does not reference kcov_kaslr_base:"
		echo "$canon_body" | sed 's/^/    /'
		echo "  fix: kcov_canon_cmp_ip() must subtract kcov_kaslr_base"
		echo "       from its argument; without that the on-disk cmp_ip"
		echo "       is the raw runtime PC again and cross-reboot warm-"
		echo "       loads silently alias every learned constant."
	} >&2
	echo "FAIL: $NAME: kcov_canon_cmp_ip() missing kcov_kaslr_base subtraction"
	exit 1
fi

# 2. Every function in cmp_hints.c that calls cmp_hints_bloom_check_and_set
#    OR pool_add_locked() must also call kcov_canon_cmp_ip() somewhere in
#    the same body.  Walks cmp_hints.c function-by-function: a function
#    header is a line that starts at column 0 with a return type and a
#    paren, and the matching close brace also starts at column 0.
#    cmp_hints.c follows that style throughout so the heuristic is
#    reliable.  cmp_hints_flush_pending is whitelisted (see file header).
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
		has_ingress = 0
		next
	}
	in_body {
		if (index($0, "kcov_canon_cmp_ip") > 0) has_canon = 1
		if (name != "cmp_hints_flush_pending" &&
		    (index($0, "cmp_hints_bloom_check_and_set") > 0 ||
		     index($0, "pool_add_locked") > 0))
			has_ingress = 1
	}
	in_body && /^}/ {
		if (has_ingress && !has_canon)
			printf("%s:%d: %s\n", FILENAME, header_line, name)
		in_body = 0
		want = 0
	}
' cmp_hints.c)"

if [ -n "$missing" ]; then
	{
		echo "  $NAME: function(s) reach the cmp-hints bloom or pool but never canonicalise cmp_ip:"
		echo "$missing" | sed 's/^/    /'
		echo "  fix: the only canonical cmp_ip in this codebase comes"
		echo "       from kcov_canon_cmp_ip().  The enclosing function"
		echo "       must have routed the raw KCOV cmp record IP through"
		echo "       kcov_canon_cmp_ip before reaching either ingress,"
		echo "       or pass the canonical value down from a caller that"
		echo "       did (and is itself covered by this check)."
	} >&2
	echo "FAIL: $NAME: cmp-hints ingress reached without kcov_canon_cmp_ip"
	exit 1
fi

echo "PASS: $NAME: cmp_hints bloom/pool fed only by kcov_canon_cmp_ip'd cmp_ip"
exit 0
