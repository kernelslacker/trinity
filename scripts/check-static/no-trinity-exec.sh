#!/bin/bash
#
# no-trinity-exec: nothing in the static battery may start trinity.
#
# check-static has to stay runnable on hosts where the fuzzer must not run,
# so neither scripts/check-static.sh nor any script beside it may name the
# binary (any path whose last component is trinity: $TRINITY_PATH/trinity,
# ./trinity, $(pwd)/trinity), a launcher or process tool (run-trinity.sh,
# killtrin.sh, trinity-gdb-*.sh, test-multi.sh, test-vm.sh, rand-vm.sh,
# test-all-syscalls-*.sh, find.sh) or the opt-in runtime fixture and its
# make target (check-runtime*).  A check that needs live output belongs in
# that fixture, which only `make check-runtime` runs.
#
# Whole-line comments are skipped, so a gate may cite the fixture, and a
# path has to end in trinity to match, so cache and tmp paths that merely
# contain the word do not.  A binary found on PATH, or a path assembled
# somewhere else, is not caught: this is a tripwire, not a sandbox.  This
# file is exempt from its own scan because it has to spell the patterns.

set -u

NAME="no-trinity-exec"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

# One extended regex per alternative.  The script names are the ones under
# scripts/ that start or wrap trinity; find.sh needs a word boundary so
# that a helper such as lib-find.sh does not match.
patterns=(
	'run-trinity'
	'killtrin'
	'trinity-gdb-(wrap|attach)\.sh'
	'test-all-syscalls-[a-z]*\.sh'
	'test-multi\.sh'
	'test-vm\.sh'
	'rand-vm\.sh'
	'(^|[^A-Za-z0-9_.-])find\.sh'
	'check-runtime'
	'/trinity([^A-Za-z0-9_./-]|$)'
)
PATTERN="$(IFS='|'; echo "${patterns[*]}")"

# scan_file FILE: print "LINE:TEXT" for each non-comment line of FILE that
# matches PATTERN, and succeed only if there was one.  Comment lines are
# blanked rather than dropped so the line numbers stay those of the file.
scan_file() {
	sed -E 's/^[[:space:]]*#.*$//' "$1" | grep -n -E -e "$PATTERN"
}

# Self-test: a detector that stopped matching, or one that started matching
# cache paths, would pass or fail the whole battery for the wrong reason.
# The must-pass lines from LINUS_HDR_CACHE down are the cache, tmp and
# awk-comment lines in uapi-shim-values.sh that merely contain the word.
# The fixtures are literal text, so the single quotes are deliberate.
# shellcheck disable=SC2016
must_fire=(
	'"$ROOT/scripts/run-trinity.sh" --dry-run -C 4'
	'( cd "$WORK" && ./trinity -C 4 )'
	'ln -sf "$ROOT/trinity" "$WORK/trinity"'
	'"$TRINITY_PATH/trinity" -L'
	'${TRINITY_PATH}/trinity -c ftruncate'
	'timeout 5 "$(pwd)/trinity" -V'
	'/usr/local/bin/trinity --version'
	'"$SCRIPT_DIR/../trinity" --version'
	'"$SCRIPT_DIR/killtrin.sh"'
	'"$SCRIPT_DIR/trinity-gdb-wrap.sh" -c mmap'
	'bash scripts/trinity-gdb-attach.sh'
	'scripts/test-all-syscalls-parallel.sh'
	'scripts/test-all-syscalls-sequentially.sh'
	'scripts/test-multi.sh'
	'scripts/test-vm.sh'
	'scripts/rand-vm.sh'
	'scripts/find.sh'
	'make check-runtime'
	'"$ROOT/scripts/check-runtime-json-output.sh"'
)
# shellcheck disable=SC2016
must_pass=(
	'# ./trinity is never run from here'
	'	# "$ROOT/trinity" in a comment'
	'cat "$ROOT/trinity.log"'
	'. "$(dirname "$0")/lib-find.sh"'
	'LINUS_HDR_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/trinity/linus-hdrs-${LINUS_HASH}"'
	'BUILD_SCRATCH=$(mktemp -d /tmp/trinity-linus-build-XXXXXX)'
	'    if (!(sym in harvest)) next  # not a trinity shim -- skip'
)

selftest_dir="$(mktemp -d)" || fail "mktemp failed"
trap 'rm -rf "$selftest_dir"' EXIT
probe="$selftest_dir/probe.sh"
for line in "${must_fire[@]}"; do
	printf '%s\n' "$line" > "$probe"
	scan_file "$probe" > /dev/null || fail "self-test: missed: $line"
done
for line in "${must_pass[@]}"; do
	printf '%s\n' "$line" > "$probe"
	if scan_file "$probe" > /dev/null; then
		fail "self-test: false positive: $line"
	fi
done

scripts=("$ROOT/scripts/check-static.sh")
for f in "$ROOT"/scripts/check-static/*.sh; do
	[ "$(basename "$f")" = "$NAME.sh" ] && continue
	scripts+=("$f")
done

# An unreadable file would scan as clean, so it is an error instead.
for f in "${scripts[@]}"; do
	[ -r "$f" ] || fail "cannot read ${f#"$ROOT"/}"
done

fail_count=0
for f in "${scripts[@]}"; do
	if hits="$(scan_file "$f")"; then
		fail_count=$((fail_count + 1))
		printf '%s\n' "$hits" | sed "s|^|  ${f#"$ROOT"/}:|" >&2
	fi
done

if [ "$fail_count" -gt 0 ]; then
	{
		echo "FAIL: $NAME: $fail_count script(s) name the trinity binary, a launcher or the runtime fixture"
		echo "  check-static has to stay runnable where trinity must not run; a check that"
		echo "  needs the binary belongs in scripts/check-runtime-json-output.sh"
		echo "  (make check-runtime), not in scripts/check-static/."
	} >&2
	exit 1
fi

echo "PASS: $NAME: ${#scripts[@]} script(s) scanned, none name the trinity binary, a launcher or the runtime fixture"
exit 0
