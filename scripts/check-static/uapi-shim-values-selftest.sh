#!/bin/bash
#
# uapi-shim-values-selftest: run uapi-shim-values on a scratch tree and pin the
# verdicts that must not depend on the build host or its caller: a baseline
# entry its headers predate is skipped, a stale one or a wrong value fails, a
# symbol only the Tier-2 kernel tree resolves is checked even under a hook's
# GIT_DIR, a macro no probe header declares is compared with its definition in
# the tree's installed headers, a constant that needs 64 bits is compared on
# all of them, and unresolved symbols are one count.  No git runs here: a stub
# answers the gate's revision lookup.

set -u

NAME="uapi-shim-values-selftest"
GATE="$(dirname "$0")/uapi-shim-values.sh"

work="$(mktemp -d)" || { echo "FAIL: $NAME: mktemp failed"; exit 1; }
trap 'rm -rf "$work"' EXIT

tree="$work/tree"
mkdir -p "$tree/scripts/check-static"

# NDA_DST resolves on any host with linux/neighbour.h.  Nothing declares
# SELFTEST_NEWER_THAN_HOST, which stands in for a constant newer than the
# host's headers, HAVE_SELFTEST_SWITCH, which has a known-private prefix, or
# SELFTESTNOUNDERSCORE.
cat > "$tree/shims.h" <<'EOF'
#ifndef NDA_DST
#define NDA_DST 1
#endif
#ifndef SELFTEST_NEWER_THAN_HOST
#define SELFTEST_NEWER_THAN_HOST 99
#endif
#define HAVE_SELFTEST_SWITCH 1
#define SELFTESTNOUNDERSCORE 7
EOF

# The scratch tree harvests a handful of symbols, so every ratchet floor is 1.
for floor in harvest probed tier1-probed text hdr; do
	echo 1 > "$tree/scripts/check-static/uapi-shim-$floor-floor.baseline"
done

# run_gate BASELINE [VAR=VALUE...]: run the gate on the scratch tree with
# BASELINE as its baseline file.  Leaves the exit status in $rc and the
# output in $work/out and $work/err.  TRINITY_LINUS_SRC and
# UAPI_SHIM_VALUES_LIST are dropped so a developer's own kernel tree or
# listing request cannot change the outcome; cases add them back in "$@".
run_gate() {
	printf '%s\n' "$1" > "$tree/scripts/check-static/uapi-shim-values.baseline"
	shift
	rc=0
	env -u TRINITY_LINUS_SRC -u UAPI_SHIM_VALUES_LIST REPO_ROOT="$tree" "$@" "$GATE" \
		> "$work/out" 2> "$work/err" || rc=$?
}

pass=0
fail=0

# expect LABEL COMMAND...: count a success of COMMAND as a pass, and show
# what the gate printed when it is not one.
expect() {
	local label="$1"
	shift
	if "$@"; then
		pass=$((pass + 1))
	else
		echo "  $NAME: FAIL: $label" >&2
		sed 's/^/    stdout: /' "$work/out" >&2
		sed 's/^/    stderr: /' "$work/err" >&2
		fail=$((fail + 1))
	fi
}

# Case 1: the tree shims the baseline symbol but no probe resolves it.
# Skipped and counted.
run_gate "NDA_DST 1
SELFTEST_NEWER_THAN_HOST 99"
expect "unresolvable baseline symbol: gate passes" [ "$rc" -eq 0 ]
expect "unresolvable baseline symbol: SKIP line names it" \
	grep -q '^SKIP: uapi-shim-values: baseline symbol SELFTEST_NEWER_THAN_HOST ' "$work/err"
expect "unresolvable baseline symbol: counted in the PASS line" \
	grep -q 'baseline-skipped 1 ' "$work/out"

# Case 2: a baseline symbol the host does resolve, pinned to the wrong value.
run_gate "NDA_DST 2"
expect "wrong pinned value: gate fails" [ "$rc" -ne 0 ]
expect "wrong pinned value: names the symbol and both values" \
	grep -q 'baseline NDA_DST: compiler says 1, baseline says 2' "$work/err"

# Case 3: the tree has no shim for the baseline symbol, so it is never probed
# and no host could resolve it.  Stale, not skipped.
run_gate "NDA_DST 1
SELFTEST_NO_SUCH_SHIM 5"
expect "baseline symbol without a shim: gate fails" [ "$rc" -ne 0 ]
expect "baseline symbol without a shim: named as stale" \
	grep -q 'baseline symbol SELFTEST_NO_SUCH_SHIM has no integer #define in the tree' "$work/err"

# Case 4: reporting.  Three symbols stay unresolved: one uapi-shaped, one with
# a known-private prefix and one with no underscore.  All are counted, and only
# the uapi-shaped one is named, and only when asked for.
run_gate "NDA_DST 1"
expect "unresolved symbols: counted in the PASS line" \
	grep -q 'unresolved-uapi 1 / not-uapi-shaped 2 ' "$work/out"
expect "unresolved symbols: one summary line" \
	grep -q '^WARN: uapi-shim-values: 1 uapi-shaped symbol(s) unresolved by any probe' "$work/err"
expect "unresolved symbols: none named by default" \
	test "$(grep -c -e SELFTEST_NEWER_THAN_HOST -e HAVE_SELFTEST_SWITCH -e SELFTESTNOUNDERSCORE "$work/err")" -eq 0
expect "unresolved symbols: no kernel tree, nothing verified from header text" \
	grep -q 'text-verified 0 ' "$work/out"
expect "unresolved symbols: no kernel tree, no header compiled" \
	grep -q 'hdr-verified 0 ' "$work/out"

run_gate "NDA_DST 1" UAPI_SHIM_VALUES_LIST=1
expect "listing requested: names the uapi-shaped symbol" \
	grep -q '^WARN: uapi-shim-values: unresolved uapi-shaped symbol: SELFTEST_NEWER_THAN_HOST$' "$work/err"
expect "listing requested: leaves out the other two" \
	test "$(grep -c -e HAVE_SELFTEST_SWITCH -e SELFTESTNOUNDERSCORE "$work/err")" -eq 0

# Case 5: the host cannot resolve the symbol but the Tier-2 kernel tree can.
# The gate keys its header cache on the tree's git revision, so a stub git
# answers 0123abc and a pre-seeded cache stands in for headers_install; its
# neighbour.h defines the symbol on top of the host's header.  Its
# selftest_text.h is a header no probe set includes, which only the text
# lookup of Case 7 reads, and its selftest_hdr.h one that declares an
# expression and an enum member, which only the per-header probe of Case 8
# can evaluate.  Like the real git, the stub answers for the caller's
# repository if GIT_* redirects it.
linus="$work/linus"
hdrs="$work/cache/trinity/linus-hdrs-0123abc/include"
mkdir -p "$linus/include/uapi" "$work/bin" "$hdrs/linux"
cat > "$work/bin/git" <<'EOF'
#!/bin/sh
if env | grep -qE '^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|COMMON_DIR|PREFIX)='; then
	echo callers-revision
else
	echo 0123abc
fi
EOF
chmod +x "$work/bin/git"
: > "$hdrs/linux/version.h"
printf '#include_next <linux/neighbour.h>\n#define SELFTEST_NEWER_THAN_HOST 99\n' \
	> "$hdrs/linux/neighbour.h"
printf '#define SELFTESTNOUNDERSCORE 7\n' > "$hdrs/linux/selftest_text.h"
cat > "$hdrs/linux/selftest_hdr.h" <<'EOF'
#define SELFTEST_HDR_MASK ((1 << 3) | (1 << 5))
enum selftest_hdr_attr {
	SELFTEST_HDR_UNSPEC,
	SELFTEST_HDR_ONE,
	SELFTEST_HDR_TWO,
};
EOF
cat > "$tree/hdr-shims.h" <<'EOF'
#define SELFTEST_HDR_MASK	40
#define SELFTEST_HDR_TWO	2
EOF
# Constants that need 64 bits are compared on all of them: UINT64_MAX and
# INT64_MAX from the host's stdint.h, and SELFTEST_WIDE_NEWER from the
# neighbour.h above, which Tier 2 evaluates.  UINT32_MAX and AT_FDCWD do not
# need them, and their shims are the 32-bit unsigned spellings of an unsigned
# int and of an int, which have to go on matching.
printf '#define SELFTEST_WIDE_NEWER (1ULL << 40)\n' >> "$hdrs/linux/neighbour.h"
cat > "$tree/wide-shims.h" <<'EOF'
#define UINT32_MAX	0xffffffff
#define AT_FDCWD	0xffffff9c
#define UINT64_MAX	0xffffffffffffffff
#define INT64_MAX	0x7fffffffffffffff
#define SELFTEST_WIDE_NEWER	(1ULL<<40)
EOF
tier2=(TRINITY_LINUS_SRC="$linus" XDG_CACHE_HOME="$work/cache" PATH="$work/bin:$PATH")

run_gate "SELFTEST_NEWER_THAN_HOST 99" "${tier2[@]}"
expect "tier2-resolved baseline symbol: gate passes" [ "$rc" -eq 0 ]
expect "tier2-resolved baseline symbol: checked, not skipped" \
	grep -q 'baseline-skipped 0 ' "$work/out"
expect "tier2 tree: the one macro only its header text declares is verified" \
	grep -q 'text-verified 1 ' "$work/out"
expect "tier2 tree: the expression and the enum member only their header evaluates are verified" \
	grep -q 'hdr-verified 2 ' "$work/out"
expect "wide constants: the three that need 64 bits are compared on all of them" \
	grep -q 'wide-checked 3 ' "$work/out"

# Only the high half of each wide shim is wrong now, which the int view of the
# constant cannot see: UINT64_MAX spelled as the 32-bit all-ones, INT64_MAX
# and the Tier-2 constant with a high bit moved.
cp "$tree/wide-shims.h" "$work/wide-shims.good"
cat > "$tree/wide-shims.h" <<'EOF'
#define UINT32_MAX	0xffffffff
#define AT_FDCWD	0xffffff9c
#define UINT64_MAX	0xffffffff
#define INT64_MAX	0x3fffffffffffffff
#define SELFTEST_WIDE_NEWER	(1ULL<<41)
EOF
run_gate "SELFTEST_NEWER_THAN_HOST 98" "${tier2[@]}"
expect "tier2-resolved baseline symbol, wrong value: gate fails" [ "$rc" -ne 0 ]
expect "tier2-resolved baseline symbol, wrong value: names both values" \
	grep -q 'baseline SELFTEST_NEWER_THAN_HOST: compiler says 99, baseline says 98' "$work/err"
for row in \
	"UINT64_MAX|0xffffffff|0x00000000ffffffff|0xffffffffffffffff" \
	"INT64_MAX|0x3fffffffffffffff|0x3fffffffffffffff|0x7fffffffffffffff" \
	"SELFTEST_WIDE_NEWER|2199023255552|0x0000020000000000|0x0000010000000000"; do
	IFS='|' read -r sym have norm want <<< "$row"
	expect "wide constant, $sym: names both 64-bit values" \
		grep -qF "FAIL: uapi-shim-values: $sym shim wrong: have $have (=$norm), want $want (compiler)" "$work/err"
done
expect "wide constants: the narrow ones, spelled unsigned, are not named" \
	test "$(grep -c -e UINT32_MAX -e AT_FDCWD "$work/err")" -eq 0
cp "$work/wide-shims.good" "$tree/wide-shims.h"

# Case 6: a hook or rebase exec exports GIT_DIR and friends.  They must not
# pick the revision the header cache is keyed on, or Tier 2 misses its cache.
run_gate "SELFTEST_NEWER_THAN_HOST 99" "${tier2[@]}" GIT_DIR=/nonexistent \
	GIT_WORK_TREE=/nonexistent GIT_INDEX_FILE=/nonexistent \
	GIT_OBJECT_DIRECTORY=/nonexistent GIT_COMMON_DIR=/nonexistent GIT_PREFIX=x/
expect "inherited GIT_DIR: gate still finds the Tier-2 cache" [ "$rc" -eq 0 ]
expect "inherited GIT_DIR: baseline symbol checked, not skipped" \
	grep -q 'baseline-skipped 0 ' "$work/out"

# Case 7: a macro no probe header declares is compared with its definition in
# the headers the kernel tree installs.  The shims are the shapes the harvest
# reads: a literal, a single-bit shift, a negative, a hex value that wraps to
# a negative int, a literal with a suffix, one in parentheses and a shift with
# a suffix.  SELFTEST_TEXT_EXPR is the start of an expression, which is not
# a literal and is not harvested: read as 4 it would not match the header's 7.
# SELFTEST_TEXT_SAME is defined twice, alike.  The header
# defines SELFTEST_TEXT_TWICE with two values and SELFTEST_TEXT_ALIAS as
# another macro, which the text lookup may not judge: they are left to the
# per-header probe, whose compiler reads the 4 of the branch cpp keeps and
# the literal's 5.
cat > "$tree/text-shims.h" <<'EOF'
#define SELFTEST_TEXT_LITERAL	5
#define SELFTEST_TEXT_SHIFT	(1<<4)
#define SELFTEST_TEXT_NEGATIVE	-4
#define SELFTEST_TEXT_HEX	0x80000001
#define SELFTEST_TEXT_SUFFIX	5UL
#define SELFTEST_TEXT_PAREN	(7)
#define SELFTEST_TEXT_USHIFT	(1UL << 4)
#define SELFTEST_TEXT_EXPR	4 + 3
#define SELFTEST_TEXT_SAME	12
#define SELFTEST_TEXT_TWICE	4
#define SELFTEST_TEXT_ALIAS	5
EOF
cat > "$work/text-header.good" <<'EOF'
#define SELFTESTNOUNDERSCORE 7
#define SELFTEST_TEXT_LITERAL 5
#define SELFTEST_TEXT_SHIFT (1 << 4)
#define SELFTEST_TEXT_NEGATIVE -4
#define SELFTEST_TEXT_HEX 0x80000001U
#define SELFTEST_TEXT_SUFFIX 5
#define SELFTEST_TEXT_PAREN 7
#define SELFTEST_TEXT_USHIFT 16
#define SELFTEST_TEXT_EXPR 7
#ifdef SELFTEST_WIDE
#define SELFTEST_TEXT_SAME 12
#define SELFTEST_TEXT_TWICE 3
#else
#define SELFTEST_TEXT_SAME 12
#define SELFTEST_TEXT_TWICE 4
#endif
#define SELFTEST_TEXT_ALIAS SELFTEST_TEXT_LITERAL
EOF
cp "$work/text-header.good" "$hdrs/linux/selftest_text.h"

run_gate "NDA_DST 1" "${tier2[@]}"
expect "header text matches: gate passes" [ "$rc" -eq 0 ]
expect "header text matches: nine shims verified" \
	grep -q 'text-verified 9 ' "$work/out"
expect "header text matches: ambiguous and aliased symbols are left to the header probe" \
	grep -q 'hdr-verified 4 ' "$work/out"
expect "header text matches: nothing but the private switch stays unresolved" \
	grep -q 'unresolved-uapi 0 / not-uapi-shaped 1 ' "$work/out"

# A wrong value is caught in every shape.  One run changes a definition of each
# shape, and the gate names every shim that no longer matches.
sed -e 's/TEXT_LITERAL 5/TEXT_LITERAL 6/' -e 's/(1 << 4)/(1 << 5)/' \
	-e 's/TEXT_NEGATIVE -4/TEXT_NEGATIVE -5/' -e 's/0x80000001U/0x80000002U/' \
	-e 's/TEXT_SUFFIX 5/TEXT_SUFFIX 6/' -e 's/TEXT_PAREN 7/TEXT_PAREN 8/' \
	-e 's/TEXT_USHIFT 16/TEXT_USHIFT 32/' \
	"$work/text-header.good" > "$hdrs/linux/selftest_text.h"
run_gate "NDA_DST 1" "${tier2[@]}"
expect "header text differs: gate fails" [ "$rc" -ne 0 ]
for row in \
	"SELFTEST_TEXT_LITERAL|5 (=5)|6" \
	"SELFTEST_TEXT_SHIFT|16 (=16)|32" \
	"SELFTEST_TEXT_NEGATIVE|-4 (=-4)|-5" \
	"SELFTEST_TEXT_HEX|0x80000001 (=-2147483647)|-2147483646" \
	"SELFTEST_TEXT_SUFFIX|5 (=5)|6" \
	"SELFTEST_TEXT_PAREN|7 (=7)|8" \
	"SELFTEST_TEXT_USHIFT|16 (=16)|32"; do
	IFS='|' read -r sym have want <<< "$row"
	expect "header text differs, $sym: names the symbol, both values and the header" \
		grep -qF "FAIL: uapi-shim-values: $sym shim wrong: have $have, want $want (installed header linux/selftest_text.h)" "$work/err"
done

# The count of verified symbols is ratcheted like the probed one.
cp "$work/text-header.good" "$hdrs/linux/selftest_text.h"
echo 99 > "$tree/scripts/check-static/uapi-shim-text-floor.baseline"
run_gate "NDA_DST 1" "${tier2[@]}"
expect "text floor above the verified count: gate fails" [ "$rc" -ne 0 ]
expect "text floor above the verified count: names both numbers" \
	grep -q 'coverage ratchet: text-verified 9 < text_floor 99' "$work/out"

# Case 8: the per-header probe.  What a literal scan cannot read, an enum
# member or an expression, is evaluated by compiling the header that declares
# it, alone.  Besides selftest_hdr.h of Case 5:
#   selftest_hdr_cast.h      casts to __u32 without including linux/types.h,
#                            so it compiles only behind the second rung's base
#                            include
#   selftest_hdr_a.h, _b.h   declare SELFTEST_HDR_TWICE as 1 and as 2
#   selftest_hdr_bad.h       includes a header that does not exist
# and selftest_hdr.h names SELFTEST_HDR_NOTE in a comment only.  The three
# symbols no header evaluates keep shims that match nothing a header says, so
# a probe that judged them anyway would fail.
echo 1 > "$tree/scripts/check-static/uapi-shim-text-floor.baseline"
cat > "$tree/hdr-more-shims.h" <<'EOF'
#define SELFTEST_HDR_NOTE	3
#define SELFTEST_HDR_CAST	12
#define SELFTEST_HDR_TWICE	3
#define SELFTEST_HDR_BAD	7
EOF
printf '/* SELFTEST_HDR_NOTE is only named here */\n' >> "$hdrs/linux/selftest_hdr.h"
printf '#define SELFTEST_HDR_CAST ((__u32)12)\n' > "$hdrs/linux/selftest_hdr_cast.h"
printf '#define SELFTEST_HDR_TWICE (0 + 1)\n' > "$hdrs/linux/selftest_hdr_a.h"
printf '#define SELFTEST_HDR_TWICE (0 + 2)\n' > "$hdrs/linux/selftest_hdr_b.h"
printf '#include <selftest_no_such_dependency.h>\n#define SELFTEST_HDR_BAD (4 + 4)\n' \
	> "$hdrs/linux/selftest_hdr_bad.h"

run_gate "NDA_DST 1" "${tier2[@]}" UAPI_SHIM_VALUES_LIST=1
expect "header probe: gate passes" [ "$rc" -eq 0 ]
expect "header probe: the expression, the enum member and the retried header are verified" \
	grep -q 'hdr-verified 5 ' "$work/out"
for sym in SELFTEST_HDR_NOTE SELFTEST_HDR_TWICE SELFTEST_HDR_BAD; do
	expect "header probe: $sym stays unresolved" \
		grep -q "^WARN: uapi-shim-values: unresolved uapi-shaped symbol: $sym\$" "$work/err"
done
expect "header probe: the verified ones are not listed as unresolved" \
	test "$(grep -c 'unresolved uapi-shaped symbol' "$work/err")" -eq 3

# One run catches a wrong value for each of the three kinds of symbol the
# probe evaluates: an expression, an enum member and a symbol whose header
# needs the retry.
cp "$tree/hdr-shims.h" "$work/hdr-shims.good"
cp "$tree/hdr-more-shims.h" "$work/hdr-more-shims.good"
sed -i -E 's/^(#define SELFTEST_HDR_(MASK|TWO|CAST)[[:space:]]+)[0-9]+$/\199/' \
	"$tree/hdr-shims.h" "$tree/hdr-more-shims.h"
run_gate "NDA_DST 1" "${tier2[@]}"
expect "header values differ: gate fails" [ "$rc" -ne 0 ]
for row in \
	"SELFTEST_HDR_MASK|40|selftest_hdr.h" \
	"SELFTEST_HDR_TWO|2|selftest_hdr.h" \
	"SELFTEST_HDR_CAST|12|selftest_hdr_cast.h"; do
	IFS='|' read -r sym want header <<< "$row"
	expect "header value differs, $sym: names the symbol, both values and the header" \
		grep -qF "FAIL: uapi-shim-values: $sym shim wrong: have 99 (=99), want $want (compiled with installed header linux/$header)" "$work/err"
done

# The count of symbols evaluated in a header is ratcheted like the others.
cp "$work/hdr-shims.good" "$tree/hdr-shims.h"
cp "$work/hdr-more-shims.good" "$tree/hdr-more-shims.h"
echo 99 > "$tree/scripts/check-static/uapi-shim-hdr-floor.baseline"
run_gate "NDA_DST 1" "${tier2[@]}"
expect "hdr floor above the verified count: gate fails" [ "$rc" -ne 0 ]
expect "hdr floor above the verified count: names both numbers" \
	grep -q 'coverage ratchet: hdr-verified 5 < hdr_floor 99' "$work/out"

total=$((pass + fail))

if [ "$fail" -gt 0 ]; then
	echo "FAIL: $NAME ($fail/$total assertions failed)"
	exit 1
fi

echo "PASS: $NAME ($pass/$total assertions)"
exit 0
