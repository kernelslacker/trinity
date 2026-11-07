#!/bin/bash
#
# scrubbed-heap-input: a syscall arg slot that blanket_address_scrub()
# walks must not be handed a zmalloc*() buffer the sanitiser leaves on
# the heap.
#
# The scrub runs avoid_shared_buffer_out() on every slot whose argtype
# carries default_address_scrub (args/argtype_table.c), after the
# sanitiser and again just before dispatch.  A heap pointer there
# overlaps the libc arena, so the scrub swaps it for a writable pool
# slot and copies nothing: the kernel reads stale pool bytes instead of
# the input the sanitiser built (recvmsg's msghdr, write()'s buffer,
# socketcall's args all went this way).  The sanitiser has to move the
# buffer itself, avoid_shared_buffer_inout() for an input,
# avoid_shared_buffer_out() for a pure output, or build it with
# get_writable_struct().
#
# Heuristic: for each struct syscallentry in syscalls/, follow its
# .sanitise and the functions of the same file it calls.  Flag a
# `rec->aN = X;` there, N a scrubbed slot, where X is a zmalloc*() call
# or a local assigned one, unless one of those functions runs
# avoid_shared_buffer_inout() or avoid_shared_buffer_out() on &rec->aN.
# The check is per slot, not per path: an assignment on another path
# than the one that moves the slot passes.
#
# A path the heuristic cannot see is listed in
# scrubbed-heap-input.baseline as `file:entry:aN`, with the reason.

set -u

NAME="scrubbed-heap-input"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/$NAME.baseline"

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

python3 - "$ROOT" "$BASELINE" > "$hits_tmp" <<'PYEOF'
import os
import re
import sys

ROOT, BASELINE = sys.argv[1], sys.argv[2]


def strip_comments(src):
    """Blank out comments, keeping every newline so offsets map to lines."""
    out = []
    i, n = 0, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            out.append(c)
            if c == '\\' and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == quote or c == '\n':
                quote = None
            i += 1
        elif src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join('\n' if ch == '\n' else ' ' for ch in src[i:j]))
            i = j
        elif src.startswith('//', i):
            while i < n and src[i] != '\n':
                i += 1
        else:
            if c in '"\'':
                quote = c
            out.append(c)
            i += 1
    return ''.join(out)


def block_end(src, start):
    depth = 0
    for i in range(start, len(src)):
        if src[i] == '{':
            depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    return len(src)


table = strip_comments(open(os.path.join(ROOT, 'args/argtype_table.c')).read())
scrubbed = {m.group(1)
            for m in re.finditer(r'\[(ARG_\w+)\]\s*=\s*\{([^}]*)\}', table)
            if re.search(r'\.default_address_scrub\s*=\s*true', m.group(2))}
if not scrubbed:
    sys.exit('no default_address_scrub argtype found in args/argtype_table.c')

baseline = set()
if os.path.exists(BASELINE):
    for line in open(BASELINE):
        line = line.split('#', 1)[0].strip()
        if line:
            baseline.add(line)

FUNC_RE = re.compile(r'^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w \t*]*?[\s*]'
                     r'([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*\{', re.M)
ENTRY_RE = re.compile(r'^struct\s+syscallentry\s+(\w+)\s*=\s*\{', re.M)
SLOT_RE = re.compile(r'\[(\d)\]\s*=\s*(ARG_\w+)\b')
ZVAR_RE = re.compile(r'\b(\w+)\s*=\s*(?:\([^()]*\)\s*)?zmalloc\w*\s*\(')
BARE_RE = re.compile(r'(?:\([^()]*\)\s*)?(\w+)')

for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, 'syscalls')):
    dirnames.sort()
    for fname in sorted(filenames):
        if not fname.endswith('.c'):
            continue
        path = os.path.join(dirpath, fname)
        rel = os.path.relpath(path, ROOT)
        src = strip_comments(open(path).read())

        funcs = {}
        for m in FUNC_RE.finditer(src):
            if m.group(1) not in ('if', 'for', 'while', 'switch'):
                funcs[m.group(1)] = (m.end() - 1, block_end(src, m.end() - 1))

        for em in ENTRY_RE.finditer(src):
            body = src[em.end() - 1:block_end(src, em.end() - 1)]
            argtype = re.search(r'\.argtype\s*=\s*\{([^}]*)\}', body)
            sanitise = re.search(r'\.sanitise\s*=\s*(\w+)', body)
            if not argtype or not sanitise or sanitise.group(1) not in funcs:
                continue
            slots = sorted({int(m.group(1)) + 1
                            for m in SLOT_RE.finditer(argtype.group(1))
                            if m.group(2) in scrubbed})
            if not slots:
                continue

            reach, todo = set(), [sanitise.group(1)]
            while todo:
                f = todo.pop()
                if f in reach:
                    continue
                reach.add(f)
                a, b = funcs[f]
                todo += [c for c in re.findall(r'\b(\w+)\s*\(', src[a:b])
                         if c in funcs and c not in reach]

            for n in slots:
                if '%s:%s:a%d' % (rel, em.group(1), n) in baseline:
                    continue
                moved = re.compile(r'avoid_shared_buffer_(?:inout|out)\s*\(\s*&rec->a%d\b' % n)
                if any(moved.search(src[funcs[f][0]:funcs[f][1]]) for f in reach):
                    continue
                for f in sorted(reach):
                    a, b = funcs[f]
                    fbody = src[a:b]
                    zvars = set(ZVAR_RE.findall(fbody))
                    for asg in re.finditer(r'\brec->a%d\s*=\s*([^;=][^;]*);' % n, fbody):
                        rhs = asg.group(1).strip()
                        bare = BARE_RE.fullmatch(rhs)
                        if 'zmalloc' in rhs or (bare and bare.group(1) in zvars):
                            line = src.count('\n', 0, a + asg.start()) + 1
                            print('%s:%d: %s a%d = %s (in %s)'
                                  % (rel, line, em.group(1), n, rhs, f))
PYEOF
status=$?

if [ "$status" -ne 0 ]; then
	echo "FAIL: $NAME: the scan did not run" >&2
	echo "FAIL: $NAME: scan error"
	exit 1
fi

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: zmalloc*() buffer(s) left on the heap in a slot the"
		echo "  blanket scrub moves without copying:"
		sed 's/^/    /' "$hits_tmp"
		echo ""
		echo "  fix: avoid_shared_buffer_inout(&rec->aN, size) after the"
		echo "       assignment for a buffer the kernel reads,"
		echo "       avoid_shared_buffer_out() for a pure output, or build"
		echo "       it with get_writable_struct().  If the assignment is"
		echo "       on a path the entry never takes, list file:entry:aN"
		echo "       in $NAME.baseline with the reason."
	} >&2
	echo "FAIL: $NAME: $n heap input(s) in scrubbed slots"
	exit 1
fi

echo "PASS: $NAME: no heap input left in a scrubbed slot"
exit 0
