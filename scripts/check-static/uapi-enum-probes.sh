#!/bin/bash
#
# uapi-enum-probes: every enum fallback in include/kernel/ is paired with the
# configure compile-test that decides it.
#
# An enum member is not a macro, so a mirror header's #ifndef cannot tell
# whether the installed uapi header has it.  configure compile-tests the
# member (check_enum_member HEADER SYMBOL...) and emits HAVE_<SYMBOL>, and the
# mirror header defines the fallback only under
#
#	#ifndef HAVE_<SYMBOL>
#	#define <SYMBOL> <value>
#	#endif
#
# The two halves are typed by hand in two files, and a name that does not
# match fails silently.  A guard no compile-test emits is always taken, which
# puts the fallback macro over the real enum member on every host, the very
# shadowing the compile-test exists to end.  A compile-test no guard names
# probes for nothing.  This check fails on either, and on a guard whose
# #define is some other symbol's, the slip a long run of copied triples
# invites.

set -u

NAME="uapi-enum-probes"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# Vacuity floor: fewer guards than this means the scan has collapsed.  Far
# below the real count, so adding or dropping a shim never trips it.
MIN_GUARDS=50

work="$(mktemp -d)" || { echo "FAIL: $NAME: mktemp failed"; exit 1; }
trap 'rm -rf "$work"' EXIT

# probes TREE: one symbol per line, the arguments after the header of every
# check_enum_member call in TREE/configure, backslash continuations folded.
probes() {
	awk '
		/^[ \t]*check_enum_member[ \t]/ { call = 1; n = 0 }
		call {
			line = $0
			more = (line ~ /\\[ \t]*$/)
			sub(/\\[ \t]*$/, "", line)
			m = split(line, w, /[ \t]+/)
			for (i = 1; i <= m; i++)
				if (w[i] != "")
					word[n++] = w[i]
			if (!more) {
				# word[0] is the helper, word[1] the header
				for (i = 2; i < n; i++)
					print word[i]
				call = 0
			}
		}
	' "$1/configure"
}

# guards TREE: "SYMBOL FILE:LINE DEFINED" for every "#ifndef HAVE_SYMBOL" in
# TREE/include/kernel/*.h, DEFINED being the first name #defined under it.
guards() {
	local f

	for f in "$1"/include/kernel/*.h; do
		strip_c_comments "$f" | awk -v file="${f#"$1"/}" '
			/^[ \t]*#[ \t]*ifndef[ \t]+HAVE_[A-Z0-9_]+/ {
				sym = $0
				sub(/^[ \t]*#[ \t]*ifndef[ \t]+HAVE_/, "", sym)
				sub(/[^A-Z0-9_].*$/, "", sym)
				pending = sym
				at = NR
				next
			}
			pending != "" && /^[ \t]*#[ \t]*define[ \t]/ {
				def = $0
				sub(/^[ \t]*#[ \t]*define[ \t]+/, "", def)
				sub(/[^A-Za-z0-9_].*$/, "", def)
				printf "%s %s:%d %s\n", pending, file, at, def
				pending = ""
			}
		'
	done
}

# audit TREE: one line per mismatch between the probes and the guards.
audit() {
	probes "$1" | sort -u > "$work/probes"
	guards "$1" > "$work/guards"

	awk -v pfile="$work/probes" '
		FILENAME == pfile { probe[$1]; next }
		{
			sym = $1; where = $2; def = $3
			seen[sym]
			if (def != sym)
				printf "%s: #ifndef HAVE_%s guards a #define of %s\n", where, sym, def
			if (!(sym in probe))
				printf "%s: HAVE_%s has no check_enum_member probe in configure\n", where, sym
		}
		END {
			for (s in probe)
				if (!(s in seen))
					printf "configure: check_enum_member probes %s but nothing falls back on HAVE_%s\n", s, s
		}
	' "$work/probes" "$work/guards" | sort
}

# ---------------------------------------------------------------------------
# Self-test: a planted tree with every shape the rule names.  The two
# scanners and the join are three moving parts, and a broken one reads as a
# clean tree.
# ---------------------------------------------------------------------------
mkdir -p "$work/st/include/kernel"
cat > "$work/st/configure" <<'EOF'
# check_enum_member HEADER SYMBOL...: a comment is not a call.
check_enum_member()
{
	:
}
check_enum_member linux/fake.h ST_PAIRED ST_NO_GUARD \
	ST_CONTINUED
check_enum_member linux/other.h ST_SWAPPED
EOF
cat > "$work/st/include/kernel/fake.h" <<'EOF'
/*
#ifndef HAVE_ST_IN_COMMENT
#define ST_IN_COMMENT	5
#endif
*/
#ifndef HAVE_ST_PAIRED
#define ST_PAIRED	1
#endif
#ifndef HAVE_ST_CONTINUED
#define ST_CONTINUED	2
#endif
#ifndef HAVE_ST_NO_PROBE
#define ST_NO_PROBE	3
#endif
#ifndef HAVE_ST_SWAPPED
#define ST_ELSEWHERE	4
#endif
EOF

st_out="$(audit "$work/st")"
st_want="configure: check_enum_member probes ST_NO_GUARD but nothing falls back on HAVE_ST_NO_GUARD
include/kernel/fake.h:12: HAVE_ST_NO_PROBE has no check_enum_member probe in configure
include/kernel/fake.h:15: #ifndef HAVE_ST_SWAPPED guards a #define of ST_ELSEWHERE"
if [ "$st_out" != "$(printf '%s\n' "$st_want" | sort)" ]; then
	{
		echo "  $NAME: self-test reported:"
		printf '%s\n' "$st_out" | sed 's/^/    /'
		echo "  expected exactly:"
		printf '%s\n' "$st_want" | sed 's/^/    /'
		echo "  (ST_PAIRED and ST_CONTINUED are planted negatives, as is the guard"
		echo "  inside a comment and the helper's own definition and comment)"
	} >&2
	echo "FAIL: $NAME: self-test misclassified the planted tree"
	exit 1
fi

# ---------------------------------------------------------------------------
# Real run.
# ---------------------------------------------------------------------------
[ -r "$ROOT/configure" ] || { echo "FAIL: $NAME: no configure under $ROOT"; exit 1; }

guards_n="$(guards "$ROOT" | wc -l | tr -d ' ')"
if [ "$guards_n" -lt "$MIN_GUARDS" ]; then
	echo "  $NAME: only $guards_n HAVE_ guard(s) found in include/kernel/, expected >= $MIN_GUARDS." >&2
	echo "FAIL: $NAME: guard floor: $guards_n < $MIN_GUARDS"
	exit 1
fi

out="$(audit "$ROOT")"
if [ -n "$out" ]; then
	{
		echo "  $NAME: enum fallback and configure probe disagree:"
		printf '%s\n' "$out" | sed 's/^/    /'
		echo "  fix: name the symbol alike in the check_enum_member call and in the"
		echo "       #ifndef HAVE_<SYMBOL> / #define <SYMBOL> pair that falls back on it."
	} >&2
	echo "FAIL: $NAME: $(printf '%s\n' "$out" | wc -l | tr -d ' ') enum fallback/probe mismatch(es)"
	exit 1
fi

echo "PASS: $NAME: $guards_n enum fallback(s), each paired with its configure probe"
exit 0
