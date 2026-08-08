#!/bin/bash
#
# json-separator-adjacency: detect missing putchar(',') separators between
# adjacent stat_category_emit_json() calls within a function in stats/json/*.c.
#
# Background: 331e499fdb5c fixed a real malformed-JSON bug in
# dump_stats_json_netfilter_and_xfrm() (network.c:329-332) where the
# putchar(',') between ipmr_getroute_pktinfo_category and ip6mr_churn_category
# was missing.  The static schema gate reconstructs from source and never
# parses binary output, so the missing comma passed every pre-existing check.
# The runtime gate (check-runtime-json-output.sh) only covers paths the
# fixture actually exercises, leaving paths outside the baseline unvalidated.
#
# Detector: scan stats/json/*.c line-by-line per function.  Track the last
# stat_category_emit_json() call; reset tracking on any separator emit
# (putchar(',') / fputc(',' / printf(",")).  Flag any second
# stat_category_emit_json() reached with no separator between.
#
# Regression fixture: the pre-fix pre-image of dump_stats_json_netfilter_and_xfrm
# (minus the putchar between ipmr_getroute_pktinfo_category and ip6mr_churn_category)
# is replayed inline as a known-bad input; the detector must produce exactly
# one hit against it.

set -u

NAME="json-separator-adjacency"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -d "$ROOT/stats/json" ] || fail "cannot read stats/json under $ROOT"
command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"

# ---------------------------------------------------------------------------
# Core scanner: Python adjacency detector.
#
# Tracks function scope via column-0 signatures and matching braces.
# Within a function body, records the most recent stat_category_emit_json()
# symbol and line number, resets on any comma separator emit.  A second
# stat_category_emit_json() without an intervening separator is a violation.
# Prints "file:line func() prev(Ln) -> next NO SEPARATOR" per violation.
# Exits 0 when no violations, 1 when any found.
# ---------------------------------------------------------------------------

_scan() {
	python3 - "$@" <<'PYEOF'
import sys, re

EMIT_RE = re.compile(r'stat_category_emit_json\(&([A-Za-z_][A-Za-z0-9_]*)\)')
# separator: putchar(',') / fputc(',' / printf(",
SEP_RE  = re.compile(r"putchar\s*\(','\)|fputc\s*\(',|printf\s*\(\",")

violations = 0
funcs_checked = 0

for path in sys.argv[1:]:
    with open(path) as f:
        lines = f.readlines()
    current_func = None
    in_func = False
    last_emit = None
    last_line = 0
    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip('\n')
        stripped = line.lstrip()

        # Function definition: starts at column 0, has '(', not a struct/typedef/static const
        if (line and line[0] not in (' ', '\t', '#', '}', '{')
                and '(' in line
                and not re.match(r'static\s+(const|struct)\b', line)
                and not line.startswith('typedef')):
            # Extract function name: last word before '('
            m = re.match(r'.*?([A-Za-z_][A-Za-z0-9_]*)\s*\(', line)
            if m:
                current_func = m.group(1)
                in_func = False
                last_emit = None
                last_line = 0
            continue

        # Opening brace at column 0 after a function signature
        if line.rstrip() == '{' and current_func and not in_func:
            in_func = True
            funcs_checked += 1
            continue

        # Closing brace at column 0 ends the function
        if line.rstrip() == '}' and in_func:
            in_func = False
            current_func = None
            last_emit = None
            last_line = 0
            continue

        if not in_func:
            continue

        # Separator emit: reset tracking
        if SEP_RE.search(stripped):
            last_emit = None
            last_line = 0
            continue

        # stat_category_emit_json call
        m = EMIT_RE.search(stripped)
        if m:
            sym = m.group(1)
            sym_short = re.sub(r'_category$', '', sym)
            if last_emit is not None:
                print(f"{path}:{lineno} {current_func}() {last_emit}(L{last_line}) -> {sym_short} NO SEPARATOR")
                violations += 1
            last_emit = sym_short
            last_line = lineno

print(f"funcs={funcs_checked}")
sys.exit(0 if violations == 0 else 1)
PYEOF
}

# ---------------------------------------------------------------------------
# Regression fixture: replay the pre-fix pre-image of
# dump_stats_json_netfilter_and_xfrm to verify the detector catches the
# historical missing-separator bug (331e499fdb5c^).
#
# The snippet reproduces the offending function tail verbatim, omitting the
# putchar(',') that was added between ipmr_getroute_pktinfo_category and
# ip6mr_churn_category.  The detector must report exactly one violation.
# ---------------------------------------------------------------------------

FIXTURE_FILE="$(mktemp /tmp/json-sep-fixture.XXXXXX.c)"
trap 'rm -f "$FIXTURE_FILE"' EXIT

cat > "$FIXTURE_FILE" <<'__FIXTURE__'
void dump_stats_json_netfilter_and_xfrm(void)
{
	stat_category_emit_json(&ipmr_cache_report_category);
	putchar(',');
	stat_category_emit_json(&ipmr_getroute_pktinfo_category);
	stat_category_emit_json(&ip6mr_churn_category);
}
__FIXTURE__

fixture_output="$(_scan "$FIXTURE_FILE" 2>/dev/null)"
fixture_hits="$(echo "$fixture_output" | grep 'NO SEPARATOR' | wc -l | tr -d ' ')"
if [ "$fixture_hits" -ne 1 ]; then
	fail "regression fixture: expected 1 violation, got $fixture_hits (detector broken)"
fi
case "$fixture_output" in
	*"ipmr_getroute_pktinfo"*"ip6mr_churn"*"NO SEPARATOR"*) ;;
	*) fail "regression fixture: hit does not name expected symbols: $fixture_output" ;;
esac

# ---------------------------------------------------------------------------
# Live scan: run the detector over all stats/json/*.c files.
# ---------------------------------------------------------------------------

hits_tmp="$(mktemp)"
trap 'rm -f "$FIXTURE_FILE" "$hits_tmp"' EXIT

_scan "$ROOT"/stats/json/*.c > "$hits_tmp" 2>&1 || true

violations="$(grep 'NO SEPARATOR' "$hits_tmp" 2>/dev/null | wc -l | tr -d ' ')"
funcs_checked="$(grep '^funcs=' "$hits_tmp" | cut -d= -f2)"

if [ "$violations" -gt 0 ]; then
	{
		echo "  $NAME: missing comma separator between adjacent stat_category_emit_json() calls:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: add putchar(',') between the two calls."
	} >&2
	echo "FAIL: $NAME: $violations violation(s) in $funcs_checked functions checked"
	exit 1
fi

echo "PASS: $NAME ($funcs_checked functions checked, 0 violations)"
exit 0
