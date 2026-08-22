#!/bin/bash
#
# shim-symbol-single-value: one fallback symbol, one value.
#
# Trinity carries hundreds of uapi fallbacks in the
#
#	#ifndef SYM
#	#define SYM <value>
#	#endif
#
# idiom, so the tree builds against kernel-headers packages that predate
# a constant.  The failure mode this check exists for is the same symbol
# being shimmed in two places with two different values.  Whichever
# translation unit compiles first is irrelevant -- each TU silently gets
# whichever copy its includes reach, and the two halves of trinity then
# disagree about the ABI while every build stays green.
#
# That is not hypothetical: struct ns_id_req shipped as a 24-byte layout
# in struct_catalog/ and a 32-byte layout in include/kernel/nsfs.h, with
# NS_ID_REQ_SIZE_VER0 defined as both 24 and 32, until 4464b8fc4301.
# The catalog wrote listns fields at offsets the sanitiser did not use.
# Nothing in the battery asked the one question that would have caught
# it, even though uapi-shim-values had both pairs sitting in its harvest.
#
# Scope: a symbol is in scope once ANY definition of it in the tree is
# guarded by `#ifndef SYM` -- i.e. it is a fallback for something the
# kernel headers may already provide, and therefore has one true value.
# Plain per-arch or per-TU constants (PTE_FILE_MAX_BITS in include/arch-*.h,
# a file-local MAX_ITERATIONS) are deliberately out of scope: they are
# allowed to differ, and they are not guarded.
#
# Values are compared numerically, so 0x20 and 32 do not count as a
# conflict.  Non-integer definitions ((1 << 3), expressions, strings) are
# not harvested at all -- conservative by construction.

set -u

NAME="shim-symbol-single-value"
ROOT="${REPO_ROOT:-$(pwd)}"

# Vacuity floor.  The guarded-symbol scan must find at least this many
# #ifndef-guarded integer shims, otherwise the awk pipeline has collapsed
# and the check would pass by finding nothing.  Same rationale as the
# harvest floor in uapi-shim-values; deliberately far below the real
# count (~1400) so ordinary shim churn never trips it.
MIN_GUARDED=500

# scan_tree ROOT_DIR
#
# Emit "SYM VALUE FILE:LINE GUARDED" for every integer #define in the
# tree, where GUARDED is 1 when the define sits inside an `#ifndef SYM`
# block for its own name.  Comments are stripped first so a commented-out
# stale value is not harvested.
scan_tree() {
	local root="$1"

	find "$root" -path "$root/scripts" -prune -o -path '*/.git' -prune -o \
	    \( -name '*.c' -o -name '*.h' \) -print 2>/dev/null | sort | \
	while IFS= read -r f; do
		perl -0777 -pe 's{/\*.*?\*/}{ }gs; s{//[^\n]*}{}g' "$f" 2>/dev/null | \
		awk -v file="${f#"$root"/}" '
			# Track the innermost `#ifndef SYM` still open, plus the
			# conditional nesting depth at which it was opened, so a
			# nested #if inside the guard does not close it early.
			/^[[:space:]]*#[[:space:]]*ifndef[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ {
				depth++
				sym = $0
				sub(/^[[:space:]]*#[[:space:]]*ifndef[[:space:]]+/, "", sym)
				sub(/[[:space:]].*$/, "", sym)
				guard[depth] = sym
				next
			}
			/^[[:space:]]*#[[:space:]]*(if|ifdef)([[:space:]]|$)/ { depth++; guard[depth] = ""; next }
			/^[[:space:]]*#[[:space:]]*endif/ { if (depth > 0) { guard[depth] = ""; depth-- } next }

			/^[[:space:]]*#[[:space:]]*define[[:space:]]+[A-Z][A-Z0-9_]+[[:space:]]+(0[xX][0-9a-fA-F]+|[0-9]+)[[:space:]]*$/ {
				line = $0
				sub(/^[[:space:]]*#[[:space:]]*define[[:space:]]+/, "", line)
				name = line
				sub(/[[:space:]].*$/, "", name)
				val = line
				sub(/^[^[:space:]]+[[:space:]]+/, "", val)
				gsub(/[[:space:]]+$/, "", val)

				guarded = 0
				for (d = depth; d > 0; d--)
					if (guard[d] == name) { guarded = 1; break }

				printf "%s %s %s:%d %d\n", name, val, file, NR, guarded
			}
		'
	done
}

# normalise_values reads "SYM VALUE ..." on stdin and rewrites VALUE to
# decimal so 0x20 and 32 compare equal.
normalise_values() {
	awk '{
		v = $2
		if (v ~ /^0[xX]/) {
			hex = tolower(substr(v, 3)); dec = 0
			for (i = 1; i <= length(hex); i++) {
				c = substr(hex, i, 1)
				dec = dec * 16 + index("0123456789abcdef", c) - 1
			}
			v = dec
		} else {
			v = v + 0
		}
		print $1, v, $3, $4
	}'
}

# find_conflicts reads normalised scan output on stdin and prints one
# line per symbol that is (a) shim-guarded somewhere and (b) defined with
# more than one distinct value.
find_conflicts() {
	awk '
		{
			sym = $1; val = $2; where = $3; guarded = $4
			if (guarded == 1) is_shim[sym] = 1
			key = sym SUBSEP val
			if (!(key in seen)) {
				seen[key] = 1
				nvals[sym]++
				order[sym, nvals[sym]] = val
			}
			# Every site, not just the first per value: a symbol
			# shimmed in four places needs all four listed or the
			# fix is a scavenger hunt.
			sites[key] = sites[key] sprintf("        %s\n", where)
		}
		END {
			for (sym in nvals) {
				if (!is_shim[sym] || nvals[sym] < 2)
					continue
				printf "%s\n", sym
				for (i = 1; i <= nvals[sym]; i++) {
					val = order[sym, i]
					printf "      = %s\n%s", val, sites[sym, val]
				}
			}
		}
	' | sed '/^$/d'
}

# ---------------------------------------------------------------------------
# Self-test: prove the detector fires.
#
# A gate that reports "0 conflicts" is indistinguishable from a gate whose
# scanner silently stopped working, and this one has three moving parts
# (the guard tracker, the hex normaliser, the conflict join).  Plant a
# conflicting pair in a scratch tree -- one guarded shim, one unguarded
# redefinition, expressed in different bases -- and require a hit.  Also
# plant an unguarded-only conflict and require it to be IGNORED, so the
# scope rule is exercised in both directions.
# ---------------------------------------------------------------------------
selftest_dir="$(mktemp -d)"
trap 'rm -rf "$selftest_dir"' EXIT

mkdir -p "$selftest_dir/a" "$selftest_dir/b"
cat > "$selftest_dir/a/shim.h" <<'EOF'
#ifndef TRINITY_SELFTEST_SHIM
#define TRINITY_SELFTEST_SHIM	32
#endif
EOF
cat > "$selftest_dir/b/other.c" <<'EOF'
#define TRINITY_SELFTEST_SHIM 0x18
#define TRINITY_SELFTEST_PLAIN 1
EOF
cat > "$selftest_dir/a/plain.c" <<'EOF'
#define TRINITY_SELFTEST_PLAIN 2
EOF

st_out="$(scan_tree "$selftest_dir" | normalise_values | find_conflicts)"

if ! printf '%s\n' "$st_out" | grep -q '^TRINITY_SELFTEST_SHIM$'; then
	echo "  $NAME: self-test FAILED -- planted 32-vs-0x18 shim conflict was not detected." >&2
	echo "  the scanner, the hex normaliser or the conflict join is broken;" >&2
	echo "  a clean run of this check would be meaningless." >&2
	echo "FAIL: $NAME: self-test did not detect a planted conflict"
	exit 1
fi
if printf '%s\n' "$st_out" | grep -q '^TRINITY_SELFTEST_PLAIN$'; then
	echo "  $NAME: self-test FAILED -- an UNGUARDED 1-vs-2 conflict was reported." >&2
	echo "  per-arch and file-local constants are allowed to differ; reporting" >&2
	echo "  them would bury the real hits in noise." >&2
	echo "FAIL: $NAME: self-test reported an out-of-scope conflict"
	exit 1
fi

# ---------------------------------------------------------------------------
# Real run.
# ---------------------------------------------------------------------------
cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

scan_out="$(scan_tree "$ROOT" | normalise_values)"

guarded_n="$(printf '%s\n' "$scan_out" | awk '$4 == 1' | wc -l | tr -d ' ')"
if [ "$guarded_n" -lt "$MIN_GUARDED" ]; then
	echo "  $NAME: only $guarded_n guarded shim define(s) found, expected >= $MIN_GUARDED." >&2
	echo "  the scan pipeline has collapsed -- this is not a clean tree." >&2
	echo "FAIL: $NAME: guarded-shim floor: $guarded_n < $MIN_GUARDED"
	exit 1
fi

conflicts="$(printf '%s\n' "$scan_out" | find_conflicts)"
n="$(printf '%s\n' "$conflicts" | grep -c '^[A-Z]' || true)"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: shim symbol(s) defined with more than one value:"
		printf '%s\n' "$conflicts" | sed 's/^\([A-Z]\)/    \1/'
		echo "  fix: keep one definition, in the include/kernel/ shim header,"
		echo "       and include that header from every consumer.  Two values"
		echo "       for one uapi symbol means two TUs disagree about the ABI."
	} >&2
	echo "FAIL: $NAME: $n shim symbol(s) with conflicting values"
	exit 1
fi

echo "PASS: $NAME: $guarded_n guarded shim(s), 0 conflicting values"
exit 0
