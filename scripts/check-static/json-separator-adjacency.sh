#!/bin/bash
#
# json-separator-adjacency: detect missing comma separators between
# adjacent stat_category_emit_json() calls within a function in stats/json/*.c.
#
# Background: 872757fb803b ("stats/json: fix missing comma before ip6mr_churn
# in network section") fixed a real malformed-JSON bug in
# dump_stats_json_netfilter_and_xfrm() (network.c:329-332) where the
# putchar(',') between ipmr_getroute_pktinfo_category and ip6mr_churn_category
# was missing.  The static schema gate reconstructs from source and never
# parses binary output, so the missing comma passed every pre-existing check.
# The runtime gate (check-runtime-json-output.sh) only covers paths the
# fixture actually exercises, leaving paths outside the baseline unvalidated.
#
# Detector: scan stats/json/*.c line-by-line per function.  Two directions,
# because a comma can be wrong in two ways:
#
#   NO SEPARATOR   - two stat_category_emit_json() calls with no separator
#                    between them, i.e. a missing comma (the 872757fb803b bug).
#   ORPHAN SEPARATOR - two separators with no emit between them, i.e. a comma
#                    with nothing to separate.  This is what deleting a stats
#                    category leaves behind: the category's emit line goes and
#                    its json_stats_sep() stays, producing ",," and a document
#                    that no JSON parser will accept.  Categories get deleted
#                    routinely now (the childop burns), so this direction is
#                    not hypothetical -- it was found by the runtime gate
#                    while this check, whose entire subject is separator
#                    adjacency, passed the same tree.
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
# separator: the json_stats_sep() helper, or a hand-written comma emit
# (putchar(',') / fputc(',' / printf(",).  json_stats_sep() is the
# supported form -- it decides positionally, so it is correct both as the
# first member of an object and as a later one.
SEP_RE  = re.compile(r"json_stats_sep\s*\(\)|putchar\s*\(','\)|fputc\s*\(',|printf\s*\(\",")

violations = 0
funcs_checked = 0

for path in sys.argv[1:]:
    with open(path) as f:
        lines = f.readlines()
    current_func = None
    in_func = False
    last_emit = None
    last_line = 0
    last_sep_line = None
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
                last_sep_line = None
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
            last_sep_line = None
            continue

        if not in_func:
            continue

        # Separator emit: reset emit tracking, and flag a separator that
        # follows another separator with nothing but blank lines and
        # comments in between.  Deliberately strict about "nothing in
        # between": any other statement between the two separators could
        # be emitting an object of its own, and this check does not try to
        # model that.  The deletion-leftover shape it is aimed at leaves
        # exactly this residue.
        if SEP_RE.search(stripped):
            if last_sep_line is not None:
                print(f"{path}:{lineno} {current_func}() separator(L{last_sep_line}) "
                      f"-> separator ORPHAN SEPARATOR")
                violations += 1
            last_sep_line = lineno
            last_emit = None
            last_line = 0
            continue

        # Any other code between two separators clears the orphan state --
        # only blank lines and comments are transparent.
        if stripped and not stripped.startswith(('/*', '*', '//')):
            last_sep_line = None

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
            last_sep_line = None

print(f"funcs={funcs_checked}")
sys.exit(0 if violations == 0 else 1)
PYEOF
}

# ---------------------------------------------------------------------------
# Regression fixture: replay the pre-fix pre-image of
# dump_stats_json_netfilter_and_xfrm to verify the detector catches the
# historical missing-separator bug (872757fb803b^).
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
# Negative control: the same shape with json_stats_sep() must be clean, so a
# future edit that stops recognising the helper fails here rather than
# silently accepting a document with a missing comma.
SEP_FIXTURE="$(mktemp /tmp/json-sep-ok.XXXXXX.c)"
cat > "$SEP_FIXTURE" <<'__OKFIXTURE__'
void dump_stats_json_ok(void)
{
	json_stats_sep();
	stat_category_emit_json(&a_category);
	json_stats_sep();
	stat_category_emit_json(&b_category);
}
__OKFIXTURE__
if _scan "$SEP_FIXTURE" 2>/dev/null | grep -q 'NO SEPARATOR'; then
	rm -f "$SEP_FIXTURE"
	fail "negative control: json_stats_sep() not recognised as a separator"
fi
rm -f "$SEP_FIXTURE"
# Orphan-separator fixture: the residue a deleted stats category leaves --
# its json_stats_sep() with the emit line gone.  Blank lines between the two
# separators are exactly how it looks in a real deletion diff, so the fixture
# keeps them.  The detector must report exactly one ORPHAN SEPARATOR.
ORPHAN_FIXTURE="$(mktemp /tmp/json-sep-orphan.XXXXXX.c)"
cat > "$ORPHAN_FIXTURE" <<'__ORPHANFIXTURE__'
void dump_stats_json_orphan(void)
{
	json_stats_sep();


	json_stats_sep();
	stat_category_emit_json(&b_category);
}
__ORPHANFIXTURE__
orphan_output="$(_scan "$ORPHAN_FIXTURE" 2>/dev/null)"
orphan_hits="$(echo "$orphan_output" | grep -c 'ORPHAN SEPARATOR')"
rm -f "$ORPHAN_FIXTURE"
if [ "$orphan_hits" -ne 1 ]; then
	fail "orphan fixture: expected 1 ORPHAN SEPARATOR, got $orphan_hits (detector broken)"
fi

# Negative control for the orphan direction: two separators with a real emit
# between them is the normal shape and must stay silent, or every well-formed
# section in the tree becomes a false positive.
ORPHAN_OK="$(mktemp /tmp/json-sep-orphan-ok.XXXXXX.c)"
cat > "$ORPHAN_OK" <<'__ORPHANOK__'
void dump_stats_json_orphan_ok(void)
{
	json_stats_sep();
	stat_category_emit_json(&a_category);
	json_stats_sep();
	stat_category_emit_json(&b_category);
}
__ORPHANOK__
if _scan "$ORPHAN_OK" 2>/dev/null | grep -q 'ORPHAN SEPARATOR'; then
	rm -f "$ORPHAN_OK"
	fail "orphan negative control: a separated pair of emits was reported as orphaned"
fi
rm -f "$ORPHAN_OK"

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

violations="$(grep -cE 'NO SEPARATOR|ORPHAN SEPARATOR' "$hits_tmp" 2>/dev/null || true)"
funcs_checked="$(grep '^funcs=' "$hits_tmp" | cut -d= -f2)"

if [ "$violations" -gt 0 ]; then
	{
		echo "  $NAME: separator defect(s) in stats/json:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: NO SEPARATOR -- call json_stats_sep() before the second emit."
		echo "       ORPHAN SEPARATOR -- delete the json_stats_sep() whose emit is gone."
	} >&2
	echo "FAIL: $NAME: $violations violation(s) in $funcs_checked functions checked"
	exit 1
fi

echo "PASS: $NAME ($funcs_checked functions checked, 0 violations)"
exit 0
