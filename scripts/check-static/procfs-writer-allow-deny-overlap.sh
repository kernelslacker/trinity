#!/bin/bash
#
# procfs-writer-allow-deny-overlap: pin the allow/deny rule overlaps in
# childops/fs/procfs-writer.c against the .baseline beside this script.
#
# add_entry() lets an allow rule win silently over a deny rule it overlaps.
# That depends on the rule tables alone, so the overlaps are read out of the
# source and diffed against the baseline both ways: a new overlap fails until
# reviewed, and a pinned pair that stopped overlapping fails as stale.
#
# After an intentional table change, run this with --regen and review the diff.

set -u

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

NAME="procfs-writer-allow-deny-overlap"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SOURCE="$ROOT/childops/fs/procfs-writer.c"
BASELINE="$ROOT/scripts/check-static/procfs-writer-allow-deny-overlap.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$SOURCE" ] || fail "cannot read ${SOURCE#"$ROOT"/}"
command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"

MODE="check"
case "${1:-}" in
	--regen) MODE="regen" ;;
	"")      MODE="check" ;;
	*)       fail "unknown arg: $1" ;;
esac

stripped="$(mktemp)" || fail "mktemp failed"
trap 'rm -f "$stripped"' EXIT
strip_c_comments "$SOURCE" > "$stripped"

python3 - "$stripped" "$BASELINE" "$MODE" "$NAME" "$ROOT" <<'PYEOF'
import hashlib
import os
import re
import sys
from collections import namedtuple

stripped_path, baseline_path, mode, name, root = sys.argv[1:6]
baseline_rel = os.path.relpath(baseline_path, root)

PREFIX, EXACT, SUFFIX = "MATCH_PREFIX", "MATCH_EXACT", "MATCH_SUFFIX"
ANCHORED = (PREFIX, EXACT)
SHORT = {PREFIX: "PREFIX", EXACT: "EXACT", SUFFIX: "SUFFIX"}

# sha256 prefixes of the comment-stripped, whitespace-collapsed C
# definitions that rule_matches() and find_overlaps() below mirror.  A change
# to one of them can change what a rule matches: re-verify the model against
# the new C, then update the digest.
MATCHER_DIGESTS = {
    "path_under_discovery_root": "2d4f716e0c12c676",
    "rule_matches": "ab8598868a489786",
    "path_matches_table": "80dfc90836b6a37e",
    "path_denied": "bc2e83138114c61a",
    "path_allowed": "2623191e0a4ee0f5",
    "path_prefiltered": "cdb44fea1e30dce9",
}

Rule = namedtuple("Rule", "kind pattern cls")

# { "pattern", MATCH_KIND, "class" } -- the positional layout of
# struct path_rule.
RULE_RE = re.compile(
    r'\{\s*"([^"]*)"\s*,\s*(MATCH_[A-Z]+)\s*,\s*"([^"]*)"\s*\}')


def fail(msg, *detail):
    print(f"FAIL: {name}: {msg}", file=sys.stderr)
    for line in detail:
        print(f"  {line}", file=sys.stderr)
    sys.exit(1)


def rule_matches(rule, path, roots):
    # Mirrors rule_matches() in the source.  A SUFFIX rule only fires on a
    # path under a discovery root.
    if rule.kind == EXACT:
        return path == rule.pattern
    if rule.kind == PREFIX:
        return path.startswith(rule.pattern)
    return (any(path.startswith(r) for r in roots) and
            path.endswith(rule.pattern))


def find_overlaps(allow, deny, prefilter, roots):
    # A PREFIX/EXACT deny overlaps a PREFIX/EXACT allow when one pattern is a
    # leading part of the other, unless prefilter_rules[] already blocks the
    # deny pattern ahead of the allow check.  A SUFFIX deny cannot be
    # compared by pattern, so "<allow prefix>x<suffix>" is run through the
    # matchers: the pair overlaps when an allow rule admits that path, a deny
    # rule matches it and no prefilter rule blocks it.  The path need not
    # exist on a host; the pair is what the policy cannot tell apart.  A
    # table matches a path when any one of its rules does, as
    # path_matches_table() does.
    #
    # (allow kind, allow pattern, deny kind, deny pattern) ->
    # (allow rule, deny rule, synthetic path or None)
    found = {}
    for a in allow:
        for d in deny:
            example = None
            if d.kind == SUFFIX:
                # The prefix ends in '/' and the suffix starts with '/', so
                # the lone 'x' keeps the path under the allow root without a
                # double slash.
                if a.kind != PREFIX:
                    continue
                example = a.pattern + "x" + d.pattern
                if not any(rule_matches(r, example, roots) for r in allow):
                    continue
                if not any(rule_matches(r, example, roots) for r in deny):
                    continue
                if any(rule_matches(r, example, roots) for r in prefilter):
                    continue
            else:
                if a.kind not in ANCHORED:
                    continue
                shared = min(len(a.pattern), len(d.pattern))
                if a.pattern[:shared] != d.pattern[:shared]:
                    continue
                # A deny pattern the prefilter blocks, taken as a path, is
                # resolved ahead of the allow check by add_entry().
                if any(rule_matches(r, d.pattern, roots) for r in prefilter):
                    continue
            key = (SHORT[a.kind], a.pattern, SHORT[d.kind], d.pattern)
            found[key] = (a, d, example)
    return found


def selftest():
    # Synthetic tables put both arms under test whatever the real tables
    # hold: a detector that stopped finding overlaps, or started finding
    # them everywhere, would pass or fail the tree for the wrong reason.
    # Each match kind also gets a near-miss that a looser matcher would
    # wrongly accept; on the real tables such a matcher changes nothing, so
    # only these fixtures can see it.
    roots = ["/p/"]
    fixtures = [
        ("anchored overlap",
         [(PREFIX, "/p/a/")], [(PREFIX, "/p/a/b")], [],
         {("PREFIX", "/p/a/", "PREFIX", "/p/a/b")}),
        ("anchored overlap, deny is the shorter pattern",
         [(PREFIX, "/p/a/b")], [(PREFIX, "/p/a/")], [],
         {("PREFIX", "/p/a/b", "PREFIX", "/p/a/")}),
        ("anchored overlaps resolved by the prefilter",
         [(PREFIX, "/p/a/")], [(PREFIX, "/p/a/b"), (EXACT, "/p/a/c")],
         [(PREFIX, "/p/a/b"), (EXACT, "/p/a/c")], set()),
        ("prefilter EXACT rows that only prefix or suffix the deny",
         [(PREFIX, "/p/a/")], [(PREFIX, "/p/a/bc")],
         [(EXACT, "/p/a/b"), (EXACT, "/a/bc")],
         {("PREFIX", "/p/a/", "PREFIX", "/p/a/bc")}),
        ("prefilter PREFIX rows: a shorter one blocks, a mid-path one not",
         [(PREFIX, "/p/a/")], [(PREFIX, "/p/a/b/c"), (PREFIX, "/p/a/d")],
         [(PREFIX, "/p/a/b"), (PREFIX, "/a/d")],
         {("PREFIX", "/p/a/", "PREFIX", "/p/a/d")}),
        ("disjoint anchored patterns",
         [(PREFIX, "/p/a/")], [(EXACT, "/p/c")], [], set()),
        ("suffix deny under an allow prefix",
         [(PREFIX, "/p/a/")], [(SUFFIX, "/mem")], [],
         {("PREFIX", "/p/a/", "SUFFIX", "/mem")}),
        ("suffix overlap resolved by the prefilter",
         [(PREFIX, "/p/a/")], [(SUFFIX, "/mem")], [(SUFFIX, "/mem")],
         set()),
        ("prefilter SUFFIX row that only occurs mid-path",
         [(PREFIX, "/p/a/")], [(SUFFIX, "/mem")], [(SUFFIX, "/p/a")],
         {("PREFIX", "/p/a/", "SUFFIX", "/mem")}),
        ("allow prefix outside the discovery roots",
         [(PREFIX, "/q/a/")], [(SUFFIX, "/mem")], [], set()),
    ]
    for label, allow, deny, prefilter, expected in fixtures:
        tables = [[Rule(k, p, "t") for k, p in t]
                  for t in (allow, deny, prefilter)]
        got = set(find_overlaps(*tables, roots))
        if got != expected:
            fail(f"self-test: {label}: expected {sorted(expected)}, "
                 f"got {sorted(got)}")


def parse_table(src, table):
    m = re.search(r"static\s+const\s+struct\s+path_rule\s+" + table +
                  r"\s*\[\s*\]\s*=\s*\{(.*?)\n\};", src, re.DOTALL)
    if not m:
        fail(f"could not locate {table}[] in the source")
    body = m.group(1)
    rules = []
    for pattern, kind, cls in RULE_RE.findall(body):
        if kind not in SHORT:
            fail(f"{table}[] uses {kind}, which this gate does not model")
        if re.search(r"[\s\\]", pattern):
            fail(f"{table}[] pattern {pattern!r} holds whitespace or an "
                 f"escape the baseline cannot represent")
        rules.append(Rule(kind, pattern, cls))
    # Text left over once the entries are removed is a rule the extractor
    # did not read; ignoring it would pass on a partial table.
    leftover = RULE_RE.sub("", body).strip(" \t\n,")
    if leftover:
        fail(f"{table}[] holds text the extractor cannot read: "
             f"{leftover[:60]!r}")
    if not rules:
        fail(f"no rules found in {table}[]")
    return rules


def parse_roots(src):
    m = re.search(r"path_under_discovery_root\s*\([^)]*\)\s*\{(.*?)\n\}",
                  src, re.DOTALL)
    roots = re.findall(r'strncmp\s*\(\s*path\s*,\s*"([^"]+)"',
                       m.group(1)) if m else []
    if not roots:
        fail("could not read the discovery roots from "
             "path_under_discovery_root()")
    return roots


def read_baseline(path):
    pinned = set()
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            fields = text.split()
            if (len(fields) != 4 or fields[0] not in SHORT.values() or
                    fields[2] not in SHORT.values()):
                fail(f"{baseline_rel}:{lineno}: expected '<allow kind> "
                     f"<allow pattern> <deny kind> <deny pattern>', "
                     f"got: {text}")
            pinned.add(tuple(fields))
    return pinned


selftest()

with open(stripped_path) as f:
    src = f.read()

# The matcher is modelled on exactly these three kinds; a fourth one in the
# source needs the model extended before the tables mean anything here.
enum = re.search(r"enum\s+path_match\s*\{(.*?)\}", src, re.DOTALL)
if not enum:
    fail("could not locate enum path_match in the source")
kinds = re.findall(r"\bMATCH_[A-Z]+\b", enum.group(1))
if sorted(kinds) != sorted(SHORT):
    fail(f"enum path_match is {kinds}, this gate models {sorted(SHORT)}")

changed = []
for func, pinned in MATCHER_DIGESTS.items():
    m = re.search(r"^static\s+bool\s+" + func + r"\s*\([^)]*\)\s*\{.*?\n\}",
                  src, re.DOTALL | re.MULTILINE)
    if not m:
        fail(f"could not locate {func}() in the source")
    text = " ".join(m.group(0).split())
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    if digest != pinned:
        changed.append(f"{func}() digest is now {digest}, pinned {pinned}")
if changed:
    fail("matcher changed, re-verify the model", *changed,
         "rule_matches() and find_overlaps() above mirror these C functions;",
         "check them against the new C, then update MATCHER_DIGESTS.")

allow = parse_table(src, "allow_rules")
deny = parse_table(src, "deny_rules")
prefilter = parse_table(src, "prefilter_rules")
overlaps = find_overlaps(allow, deny, prefilter, parse_roots(src))
current = set(overlaps)

if mode == "regen":
    lines = [
        "# procfs-writer-allow-deny-overlap.baseline",
        "#",
        "# Allow/deny rule pairs in childops/fs/procfs-writer.c that overlap,",
        "# so the allow rule wins and the deny is ignored on the overlap.",
        "# The allow-wins order in add_entry() is intentional; the pairs are",
        "# pinned so a new one has to be reviewed and one that stops",
        "# overlapping is noticed.",
        "#",
        "# One pair per line:",
        "#   <allow kind> <allow pattern> <deny kind> <deny pattern>",
        "# A SUFFIX deny is judged on the path \"<allow prefix>x<suffix>\",",
        "# which need not exist on a host.",
        "#",
        "# Regenerate after a rule-table change with:",
        "#   scripts/check-static/procfs-writer-allow-deny-overlap.sh --regen",
        "# and commit the diff alongside the table change.",
        "",
        *(" ".join(key) for key in sorted(current)),
    ]
    with open(baseline_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"REGEN: {name}: wrote {len(current)} overlaps to {baseline_rel}")
    sys.exit(0)

if not os.path.exists(baseline_path):
    fail(f"baseline missing at {baseline_rel} -- run with --regen to seed")

pinned = read_baseline(baseline_path)
new = sorted(current - pinned)
stale = sorted(pinned - current)
if new or stale:
    print(f"FAIL: {name}: allow/deny overlaps drifted from {baseline_rel}",
          file=sys.stderr)
    for key in new:
        a, d, example = overlaps[key]
        how = (f"e.g. '{example}'" if example
               else "the patterns share a leading part")
        print(f"  new overlap, the deny is ignored on it: allow "
              f"{key[0]} '{a.pattern}' [{a.cls}] vs deny {key[2]} "
              f"'{d.pattern}' [{d.cls}] ({how})", file=sys.stderr)
    for key in stale:
        print(f"  stale baseline entry, the rules no longer overlap: "
              f"{' '.join(key)}", file=sys.stderr)
    if new:
        print("  An allow rule wins over the deny it overlaps, so that deny "
              "is not", file=sys.stderr)
        print("  enforced there.  To keep it, narrow the allow rule or list "
              "the deny", file=sys.stderr)
        print("  in prefilter_rules[].", file=sys.stderr)
    print("  If the table change is intentional, run", file=sys.stderr)
    print(f"    scripts/check-static/{name}.sh --regen", file=sys.stderr)
    print("  and commit the updated baseline alongside it.", file=sys.stderr)
    sys.exit(1)

print(f"PASS: {name}: {len(current)} allow/deny overlaps pinned")
PYEOF
