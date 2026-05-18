#!/bin/bash
#
# Trinity static (non-runtime) consistency checks.
#
# Trinity cannot safely run on developer hosts -- the binary only runs
# on an isolated fuzz machine.  Build-time and static validation
# therefore matters more here than in typical projects.  This script
# orchestrates a battery of cheap structural checks against the source
# tree so a contributor can catch architectural regressions before they
# escape to the fuzz host.
#
# Add a new check by dropping an executable file into
# scripts/check-static/.  Each check prints a single PASS/FAIL/WARN line
# on stdout (plus optional detail on stderr) and exits 0 for pass/warn,
# non-zero for fail.  See Documentation/check-static.md.
#
# Skip individual checks with CHECK_STATIC_SKIP=name1,name2.

set -u

# Locate repo root from this script's location so the target works no
# matter where make was invoked from.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CHECK_DIR="$SCRIPT_DIR/check-static"

export REPO_ROOT

SKIP="${CHECK_STATIC_SKIP:-}"

skipped() {
	local name="$1"
	[ -z "$SKIP" ] && return 1
	case ",$SKIP," in
		*,"$name",*) return 0 ;;
	esac
	return 1
}

fail_count=0
warn_count=0
ran_count=0

if [ ! -d "$CHECK_DIR" ] || [ -z "$(ls -A "$CHECK_DIR" 2>/dev/null)" ]; then
	echo "check-static: no checks installed in $CHECK_DIR"
	exit 0
fi

for check in "$CHECK_DIR"/*.sh; do
	[ -f "$check" ] || continue
	name="$(basename "$check" .sh)"

	if skipped "$name"; then
		echo "SKIP: $name (via CHECK_STATIC_SKIP)"
		continue
	fi

	ran_count=$((ran_count + 1))
	if ! "$check"; then
		fail_count=$((fail_count + 1))
	fi
done

if [ "$fail_count" -gt 0 ]; then
	echo "check-static: $fail_count check(s) failed out of $ran_count"
	exit 1
fi

echo "check-static: $ran_count check(s) passed"
exit 0
