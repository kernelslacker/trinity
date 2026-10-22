#!/bin/bash
#
# uapi-shim-values-selftest: run uapi-shim-values on a scratch tree and pin the
# verdicts that must not depend on the build host or its caller: a baseline
# entry its headers predate is skipped, a stale one or a wrong value fails, a
# symbol only the Tier-2 kernel tree resolves is checked even under a hook's
# GIT_DIR, and unresolved symbols are one count.  No git runs here: a stub
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
for floor in harvest probed tier1-probed; do
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

run_gate "NDA_DST 1" UAPI_SHIM_VALUES_LIST=1
expect "listing requested: names the uapi-shaped symbol" \
	grep -q '^WARN: uapi-shim-values: unresolved uapi-shaped symbol: SELFTEST_NEWER_THAN_HOST$' "$work/err"
expect "listing requested: leaves out the other two" \
	test "$(grep -c -e HAVE_SELFTEST_SWITCH -e SELFTESTNOUNDERSCORE "$work/err")" -eq 0

# Case 5: the host cannot resolve the symbol but the Tier-2 kernel tree can.
# The gate keys its header cache on the tree's git revision, so a stub git
# answers 0123abc and a pre-seeded cache stands in for headers_install; its
# neighbour.h defines the symbol on top of the host's header.  Like the real
# git, the stub answers for the caller's repository if GIT_* redirects it.
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
tier2=(TRINITY_LINUS_SRC="$linus" XDG_CACHE_HOME="$work/cache" PATH="$work/bin:$PATH")

run_gate "SELFTEST_NEWER_THAN_HOST 99" "${tier2[@]}"
expect "tier2-resolved baseline symbol: gate passes" [ "$rc" -eq 0 ]
expect "tier2-resolved baseline symbol: checked, not skipped" \
	grep -q 'baseline-skipped 0 ' "$work/out"

run_gate "SELFTEST_NEWER_THAN_HOST 98" "${tier2[@]}"
expect "tier2-resolved baseline symbol, wrong value: gate fails" [ "$rc" -ne 0 ]
expect "tier2-resolved baseline symbol, wrong value: names both values" \
	grep -q 'baseline SELFTEST_NEWER_THAN_HOST: compiler says 99, baseline says 98' "$work/err"

# Case 6: a hook or rebase exec exports GIT_DIR and friends.  They must not
# pick the revision the header cache is keyed on, or Tier 2 misses its cache.
run_gate "SELFTEST_NEWER_THAN_HOST 99" "${tier2[@]}" GIT_DIR=/nonexistent \
	GIT_WORK_TREE=/nonexistent GIT_INDEX_FILE=/nonexistent \
	GIT_OBJECT_DIRECTORY=/nonexistent GIT_COMMON_DIR=/nonexistent GIT_PREFIX=x/
expect "inherited GIT_DIR: gate still finds the Tier-2 cache" [ "$rc" -eq 0 ]
expect "inherited GIT_DIR: baseline symbol checked, not skipped" \
	grep -q 'baseline-skipped 0 ' "$work/out"

total=$((pass + fail))

if [ "$fail" -gt 0 ]; then
	echo "FAIL: $NAME ($fail/$total assertions failed)"
	exit 1
fi

echo "PASS: $NAME ($pass/$total assertions)"
exit 0
