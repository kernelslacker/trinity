#!/bin/bash
#
# netlink-string-floor: every netlink attribute spec drawn as a free string
# has a min_len of at least 1.
#
# spec_payload_len() (net/netlink/msg-attr-spec.c) draws an NLA_KIND_STRING
# or NLA_KIND_STRING_CPULIST payload from the spec's min_len to its max_len
# and adds no floor of its own, so a spec that leaves min_len out sends a
# zero-length payload one draw in max_len + 1.  The kernel refuses an empty
# NLA_STRING or NLA_NUL_STRING (validate_nla() in lib/nlattr.c), strict
# parse or liberal, and the whole request with it.  One byte is the NUL of
# an empty string, which both types take.
#
# The rows are read out of net/netlink/ with their comments removed: every
# { ID, NLA_KIND_STRING or NLA_KIND_STRING_CPULIST, max, min, ... }
# initializer, on one line or several, must have its fourth positional
# field, and not 0.  The _WORD and _ONEOF kinds take their length from
# their words and are not read.
#
# Sources are only read.

set -u

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

NAME="netlink-string-floor"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -d "$ROOT/net/netlink" ] || fail "cannot find net/netlink"
command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"

stripped="$(mktemp -d)" || fail "mktemp failed"
trap 'rm -rf "$stripped"' EXIT
while IFS= read -r f; do
	rel="${f#"$ROOT"/}"
	mkdir -p "$stripped/$(dirname "$rel")" || fail "mkdir failed"
	strip_c_comments "$f" > "$stripped/$rel"
done < <(find "$ROOT/net/netlink" -name '*.c' -type f | sort)

python3 - "$stripped" "$NAME" <<'PYEOF'
import re
import sys
from pathlib import Path

stripped_dir, name = sys.argv[1:3]
KIND = re.compile(r'\bNLA_KIND_STRING(?:_CPULIST)?\b')


def top_level_fields(body):
    """Split an initializer body at the commas outside nested brackets."""
    fields, depth, cur = [], 0, []
    for ch in body:
        if ch in '({[':
            depth += 1
        elif ch in ')}]':
            depth -= 1
        if ch == ',' and depth == 0:
            fields.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = ''.join(cur).strip()
    if tail:
        fields.append(tail)
    return fields


bad, rows = [], 0
for path in sorted(Path(stripped_dir).rglob('*.c')):
    src = path.read_text()
    for m in KIND.finditer(src):
        # The initializer around the kind: the nearest unmatched { before
        # it and its matching } after.
        depth, start = 0, m.start()
        while start > 0:
            start -= 1
            if src[start] == '}':
                depth += 1
            elif src[start] == '{':
                if depth == 0:
                    break
                depth -= 1
        depth, end = 0, m.end()
        while end < len(src):
            if src[end] == '{':
                depth += 1
            elif src[end] == '}':
                if depth == 0:
                    break
                depth -= 1
            end += 1
        if src[start] != '{' or end >= len(src):
            continue
        positional = [f for f in top_level_fields(src[start + 1:end])
                      if not f.startswith('.')]
        # A case label or a comparison is not a spec row.
        if len(positional) < 3 or positional[1] != m.group(0):
            continue
        rows += 1
        if len(positional) < 4 or positional[3] in ('0', '0U', '0u'):
            line = src.count('\n', 0, m.start()) + 1
            rel = path.relative_to(stripped_dir)
            bad.append(f"{rel}:{line}: {positional[0]} has no min_len of 1")

if bad:
    for b in bad:
        print(f"  {b}", file=sys.stderr)
    print(f"FAIL: {name}: {len(bad)} string spec(s) can draw an empty payload,"
          " which the kernel refuses", file=sys.stderr)
    sys.exit(1)
if rows == 0:
    print(f"FAIL: {name}: found no string spec rows, so the parse is broken",
          file=sys.stderr)
    sys.exit(1)
print(f"PASS: {name}: {rows} string spec row(s) draw at least the NUL")
PYEOF
