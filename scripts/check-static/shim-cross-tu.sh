#!/bin/bash
#
# shim-cross-tu: a .c-local uapi fallback must stay local to its .c.
#
# A fallback written into a .c file
#
#	#ifndef SYM
#	#define SYM <value>
#	#endif
#
# reaches that translation unit only.  Once another TU needs the same
# symbol -- it carries a copy of its own, or it simply uses SYM and gets
# it from the system header -- the build depends on which TUs happen to
# hold a copy.  Against a kernel-headers package that predates SYM, the
# TU without one stops compiling while the TU with one stays green, and
# the copies are free to drift apart.  A fallback more than one TU needs
# belongs in the include/kernel/<header.h> mirror of the kernel header it
# comes from (the "kernel fallback headers" of Documentation/HACKING.txt);
# that is the fix for every hit.
#
# Rule: a symbol #defined inside the true branch of an `#ifndef G` or
# `#if !defined(G)` block in a .c file fails when another .c defines it
# the same way, or when any other .c or any .h uses it.  G need not be
# the symbol itself: a family block guarded by one member counts, and so
# does a configure HAVE_ guard.  A define in the #else branch is not a
# fallback.  A use is an identifier token outside comments and string or
# character literals.  The name tested by #ifdef, #ifndef or defined(),
# the name an #undef drops, and the name a #define defines are not uses;
# a define's replacement list is.  Every *.c and *.h outside scripts/ is
# read.  Line continuations are folded before parsing.

set -u

NAME="shim-cross-tu"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

# Vacuity floor: the scan must harvest at least this many .c-local
# fallback symbols, or the parser has collapsed and a clean result means
# nothing.  Far below the real count (~400) so normal churn never trips it.
MIN_FALLBACKS=200

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"

# scan DIR: print "fallbacks N", then one block per offending symbol --
# the symbol, its fallback sites and the first use in each other file.
# Exits 0 with no offenders and 3 with offenders; anything else, an
# uncaught Python exception's 1 included, is a scanner error.
scan() {
	python3 - "$1" <<'PYEOF'
import os, re, sys

root = sys.argv[1]

def strip(text):
	"""Blank comments and literal bodies; line breaks survive."""
	out = []
	i, n = 0, len(text)
	while i < n:
		c = text[i]
		if text.startswith('/*', i):
			j = text.find('*/', i + 2)
			j = n if j < 0 else j + 2
			out.append(re.sub(r'[^\n]', ' ', text[i:j]))
			i = j
		elif text.startswith('//', i):
			j = text.find('\n', i)
			i = n if j < 0 else j
		elif c in '"\'':
			# Literals do not span lines; stop at the newline.
			j = i + 1
			while j < n and text[j] != c and text[j] != '\n':
				j += 2 if text[j] == '\\' else 1
			out.append(c + ' ' * (min(j, n) - i - 1) + c)
			i = j + 1
		else:
			out.append(c)
			i += 1
	return ''.join(out)

def logical_lines(text):
	"""(first line number, line) with backslash continuations folded."""
	buf, start = None, 0
	for lineno, line in enumerate(text.split('\n'), 1):
		if buf is None:
			buf, start = line, lineno
		else:
			buf += ' ' + line
		if buf.endswith('\\'):
			buf = buf[:-1]
			continue
		yield start, buf
		buf = None
	if buf is not None:
		yield start, buf

DIRECTIVE = re.compile(r'\s*#\s*([a-z_]+)\b(.*)$')
NOT_DEFINED = re.compile(r'\s*!\s*defined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))\s*$')
NAME = re.compile(r'\s*([A-Za-z_]\w*)')
DEFINED = re.compile(r'\bdefined\s*(?:\(\s*[A-Za-z_]\w*\s*\)|[A-Za-z_]\w*)')
TOKEN = re.compile(r'[A-Za-z_]\w*')

paths = []
for dirpath, dirnames, filenames in os.walk(root):
	top = os.path.samefile(dirpath, root)
	dirnames[:] = sorted(d for d in dirnames
			     if d != '.git' and not (top and d == 'scripts'))
	for fn in sorted(filenames):
		if fn.endswith(('.c', '.h')):
			paths.append(os.path.relpath(os.path.join(dirpath, fn), root))

fallbacks = {}		# sym -> [(file, line)], .c files only
uses = {}		# sym -> {file: first line}

def use(text, path, lineno):
	for tok in TOKEN.findall(text):
		uses.setdefault(tok, {}).setdefault(path, lineno)

for path in paths:
	try:
		with open(os.path.join(root, path), errors='replace') as f:
			text = strip(f.read())
	except OSError as e:
		print(f"error: cannot read {path}: {e}")
		sys.exit(2)
	stack = []	# guard name while in an #ifndef true branch, else None
	for lineno, line in logical_lines(text):
		d = DIRECTIVE.match(line)
		if not d:
			use(line, path, lineno)
			continue
		kw, rest = d.group(1), d.group(2)
		if kw == 'ifndef':
			m = NAME.match(rest)
			stack.append(m.group(1) if m else None)
		elif kw == 'if':
			m = NOT_DEFINED.match(rest)
			stack.append((m.group(1) or m.group(2)) if m else None)
			if not m:
				use(DEFINED.sub(' ', rest), path, lineno)
		elif kw == 'ifdef':
			stack.append(None)
		elif kw in ('elif', 'else'):
			if stack:
				stack[-1] = None
			if kw == 'elif':
				use(DEFINED.sub(' ', rest), path, lineno)
		elif kw == 'endif':
			if stack:
				stack.pop()
		elif kw == 'define':
			m = NAME.match(rest)
			if not m:
				continue
			if path.endswith('.c') and any(g is not None for g in stack):
				fallbacks.setdefault(m.group(1), []).append((path, lineno))
			use(rest[m.end():], path, lineno)

print(f"fallbacks {len(fallbacks)}")
bad = 0
for sym in sorted(fallbacks):
	sites = fallbacks[sym]
	deffiles = {p for p, _ in sites}
	users = sorted((p, l) for p, l in uses.get(sym, {}).items()
		       if p not in deffiles)
	if len(deffiles) < 2 and not users:
		continue
	bad += 1
	print(sym)
	for p, l in sites:
		print(f"\tfallback {p}:{l}")
	for p, l in users:
		print(f"\tused     {p}:{l}")
sys.exit(3 if bad else 0)
PYEOF
}

# ---------------------------------------------------------------------------
# Self-test: a planted tree with one instance of every shape the rule
# names, in both directions.  The scanner has three moving parts (the
# comment stripper, the conditional stack and the use index), and a broken
# one reads as a clean tree.
# ---------------------------------------------------------------------------
selftest_dir="$(mktemp -d)" || fail "mktemp failed"
trap 'rm -rf "$selftest_dir"' EXIT
mkdir -p "$selftest_dir/a" "$selftest_dir/b" "$selftest_dir/include" \
	"$selftest_dir/scripts"

cat > "$selftest_dir/a/one.c" <<'EOF'
#ifndef ST_DUP
#define ST_DUP		1
#endif
#ifndef ST_FAMILY_OLD
#define ST_FAMILY_OLD	2
#define ST_FAMILY_NEW	3
#endif
#ifndef ST_USED
#define ST_USED		4
#endif
#ifndef HAVE_ST_PROBED
#define ST_PROBED	5
#endif
#if !defined(ST_NOTDEF)
#define ST_NOTDEF	6
#endif
#ifndef ST_HDRUSE
#define ST_HDRUSE	7
#endif
#ifndef ST_LOCAL
#define ST_LOCAL	8
#endif
#ifndef ST_ELSE_GUARD
#define ST_ELSE_GUARD	9
#else
#define ST_ELSE		10
#endif
#ifndef ST_FOLD
#define ST_FOLD		11
#endif
#ifndef ST_MIRRORED
#define ST_MIRRORED	12
#endif
static int one[] = { ST_DUP, ST_FAMILY_OLD, ST_LOCAL, ST_ELSE, ST_FOLD,
		     ST_MIRRORED };
EOF
cat > "$selftest_dir/b/two.c" <<'EOF'
#ifndef ST_DUP
#define ST_DUP		1
#endif
/* ST_LOCAL is only named in this comment */
static const char *two = "ST_LOCAL ST_ELSE";
#ifdef ST_ELSE_GUARD
#endif
#if defined(ST_USED) || \
	defined(ST_FOLD)
#endif
#undef ST_FOLD
static int three[] = { ST_FAMILY_NEW, ST_USED, ST_PROBED, ST_NOTDEF, ST_ELSE };
EOF
cat > "$selftest_dir/include/use.h" <<'EOF'
#define ST_WRAP		(ST_HDRUSE + 1)
#ifndef ST_MIRRORED
#define ST_MIRRORED	12
#endif
EOF
cat > "$selftest_dir/scripts/skipped.c" <<'EOF'
#ifndef ST_SCRIPTS
#define ST_SCRIPTS	13
#endif
static int s = ST_LOCAL;
EOF

st_out="$(scan "$selftest_dir")"
st_rc=$?
[ "$st_rc" -eq 3 ] || fail "self-test: scan exited $st_rc on the planted tree, expected 3"
st_hits="$(printf '%s\n' "$st_out" | grep -E '^[A-Z_]+$' | sort | tr '\n' ' ')"
st_want="ST_DUP ST_FAMILY_NEW ST_HDRUSE ST_NOTDEF ST_PROBED ST_USED "
if [ "$st_hits" != "$st_want" ]; then
	{
		echo "  $NAME: self-test reported: ${st_hits:-<nothing>}"
		echo "  expected exactly:           $st_want"
		echo "  (ST_LOCAL, ST_FAMILY_OLD, ST_ELSE, ST_ELSE_GUARD, ST_FOLD,"
		echo "  ST_MIRRORED and ST_SCRIPTS are planted negatives: a comment, a"
		echo "  string, an #else define, #ifdef, a continued defined() and #undef,"
		echo "  a header's own guarded copy, and scripts/ must not fire)"
	} >&2
	fail "self-test: planted tree misclassified"
fi

# ---------------------------------------------------------------------------
# Real run.
# ---------------------------------------------------------------------------
[ -d "$ROOT" ] || fail "cannot find tree root $ROOT"
out="$(scan "$ROOT")"
rc=$?
case "$rc" in
0|3) ;;
*) fail "scanner exited $rc: $(printf '%s\n' "$out" | tail -1)" ;;
esac

harvested="$(printf '%s\n' "$out" | sed -n 's/^fallbacks //p')"
harvested="${harvested:-0}"
if [ "$harvested" -lt "$MIN_FALLBACKS" ]; then
	fail "only $harvested .c-local fallback(s) found, expected >= $MIN_FALLBACKS -- the scan has collapsed"
fi

if [ "$rc" -eq 3 ]; then
	n="$(printf '%s\n' "$out" | grep -cE '^[A-Za-z_][A-Za-z0-9_]*$')"
	{
		echo "  $NAME: .c-local fallback(s) that another TU also needs:"
		printf '%s\n' "$out" | sed -n '2,$p' | sed 's/^/    /'
		echo "  fix: move the fallback into the include/kernel/<header.h> mirror of"
		echo "       the kernel header that defines it, include the mirror where the"
		echo "       copies were and from any user no system header serves, and"
		echo "       delete the .c copies."
	} >&2
	echo "FAIL: $NAME: $n .c-local fallback symbol(s) shared across translation units"
	exit 1
fi

echo "PASS: $NAME: $harvested .c-local fallback symbol(s), none shared across translation units"
exit 0
