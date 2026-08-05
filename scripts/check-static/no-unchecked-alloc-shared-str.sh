#!/bin/bash
#
# no-unchecked-alloc-shared-str: every alloc_shared_str / alloc_shared_strdup
# assignment must have a NULL guard on the lvalue within WINDOW lines.
#
# Both functions are declared __must_check (include/utils-mem.h:119-120),
# which catches a *fully discarded* return value.  It does NOT catch the
# failure mode that matters here: assigning the return value into a variable
# and then using that variable without ever testing it against NULL.
#
# Trinity's shared-str heap has a 1 MiB ceiling so NULL is a genuinely
# reachable return.  A future caller that publishes a NULL pointer into an
# object's filename/name field would produce a strlen/free NULL-deref in the
# dump or destructor path, far from the original allocation.  The existing
# eight production call sites all handle NULL correctly; this gate keeps it
# that way.
#
# Rule: for every non-comment line of the form
#
#   <lvalue> = alloc_shared_str[dup]*(
#
# the last simple identifier component of <lvalue> must appear in an if()
# guard within the next WINDOW source lines.
#
# The tree is currently clean; this gate carries no baseline.

set -u

NAME="no-unchecked-alloc-shared-str"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

python3 - "$ROOT" > "$hits_tmp" <<'PYEOF'
import sys, re, os

ROOT   = sys.argv[1]
WINDOW = 4   # lines ahead to scan for the NULL guard

ASSIGN_RE = re.compile(
    r'([\w][\w.\->]*)\s*=\s*alloc_shared_str(?:dup)?\s*\('
)

def is_comment_line(s):
    return s.startswith('//') or s.startswith('*') or s.startswith('/*')

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = sorted(d for d in dirnames if d != '.git')
    for fname in sorted(filenames):
        if not (fname.endswith('.c') or fname.endswith('.h')):
            continue
        fpath = os.path.join(dirpath, fname)
        relpath = os.path.relpath(fpath, ROOT)
        try:
            with open(fpath) as f:
                lines = f.readlines()
        except OSError:
            continue

        for i, raw in enumerate(lines):
            stripped = raw.strip()

            # Skip pure comment lines.
            if is_comment_line(stripped):
                continue

            m = ASSIGN_RE.search(stripped)
            if not m:
                continue

            # Extract the last simple identifier from the lvalue expression.
            # e.g. "obj->map.name" → "name";  "filename" → "filename".
            lval_expr = m.group(1)
            parts = re.split(r'->|\.', lval_expr)
            last_ident = parts[-1].strip().split('[')[0]  # drop any [idx] suffix
            if not re.match(r'^\w+$', last_ident):
                continue

            # Scan the next WINDOW lines for an if() guard that names lval.
            found = False
            for j in range(i + 1, min(i + 1 + WINDOW, len(lines))):
                ahead = lines[j].strip()
                if (re.search(r'\bif\s*\(', ahead) and
                        re.search(r'\b' + re.escape(last_ident) + r'\b', ahead)):
                    found = True
                    break

            if not found:
                print(f"{relpath}:{i + 1}: {stripped}")

PYEOF

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: alloc_shared_str / alloc_shared_strdup assignment(s) with"
		echo "  no NULL guard on the lvalue within $WINDOW lines:"
		sed 's/^/    /' "$hits_tmp"
		echo ""
		echo "  fix: add 'if (lvalue == NULL) { ... }' immediately after each"
		echo "       allocation.  A NULL return is reachable (1 MiB heap ceiling);"
		echo "       publishing a NULL filename/name dereferences in dump or"
		echo "       destructor paths, far from the original allocation site."
	} >&2
	echo "FAIL: $NAME: $n unchecked alloc_shared_str/alloc_shared_strdup assignment(s)"
	exit 1
fi

echo "PASS: $NAME: 0 unchecked alloc_shared_str/alloc_shared_strdup assignments"
exit 0
