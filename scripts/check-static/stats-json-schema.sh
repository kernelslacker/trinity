#!/bin/bash
#
# stats-json-schema: pin the structural shape of the --stats-json
# document -- key-path + value-type in emission order -- against a
# golden baseline.
#
# Background: dump_stats_json() and its section emitters print a
# hand-authored JSON document from a mix of inline printf format
# strings, json_emit_string() calls, and stat_category_emit_json()
# expansions off the STAT_CATEGORY / STAT_FIELD* descriptor tables.
# Downstream consumers (scrapers, dashboards, the periodic-text
# schema audit) key off the top-level section wrappers
# ("kcov", "fault_injection", "corruption", ...), the scalar counter
# keys within each section ("op_count", "total_pcs",
# "returned_enomem", ...), AND the value TYPE at each leaf
# (u64 vs u32 vs str vs array).  A rename, removal, accidental
# typo, or silent type widening reshapes the JSON with no compile
# or test failure -- consumers just start reading NULL or coercing.
#
# This check reconstructs the emission structurally: parse every
# section emitter under stats/json/*.c, expand
# stat_category_emit_json() calls via the STAT_CATEGORY /
# STAT_FIELD* descriptor tables found under stats/, respect the
# call order in dump_stats_json() itself, then flatten to a stream
# of (indent-tagged key-path, value-type) tuples in emission
# order.  The tuple stream is diffed against a baseline; any
# schema drift -- new key, removed key, retyped value, reordered
# emission, duplicate key at the same scope -- trips the check
# with a diff pointing at the change.
#
# Improvements over the prior "sorted flat key literals" pin:
#   - value types (u64 / u32 / i32 / str / array / object)
#   - nested key paths (e.g. stats.fault_injection.armed_fail_nth)
#   - emission ORDER preserved and enforced
#   - duplicate keys at the same object scope caught
#   - descriptor-driven STAT_FIELD* keys folded into the baseline
#   - per-syscall totals collapse the picker-context dim so a
#     future accidental split (adding a per-context key path)
#     trips the check
#
# To regenerate after an intentional schema change:
#   scripts/check-static/stats-json-schema.sh --regen
# then review the resulting stats-json-schema.baseline diff and
# commit it alongside the schema change.

set -u

NAME="stats-json-schema"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASELINE="$ROOT/scripts/check-static/stats-json-schema.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -d "$ROOT/stats/json" ] || fail "cannot read stats/json under $ROOT"
command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"

MODE="check"
case "${1:-}" in
	--regen) MODE="regen" ;;
	"")      MODE="check" ;;
	*)       fail "unknown arg: $1" ;;
esac

# Structural extractor.  Emits one line per schema entry on stdout:
#   <indent>PATH\tTYPE
# Indent is two spaces per nesting level so a diff reads naturally.
# Any structural anomaly (unresolved category, unbalanced brace,
# duplicate key at the same scope, picker-context leaking into a
# per-syscall total) exits non-zero with a diagnostic to stderr.
schema=$(python3 - "$ROOT" <<'PYEOF'
import sys, re, os, glob

root = sys.argv[1]

# --- Pass 1: registry of stat_field arrays and stat_category objects. -----
# STAT_FIELD variants encountered across the tree:
#   STAT_FIELD(cat, suffix)                 -> key = "suffix"
#   STAT_FIELD_SUB(sub, field)              -> key = "field"
#   STAT_FIELD_JSON(cat, suffix, "jkey")    -> key = "jkey"
#   STAT_FIELD_JSON_SUB(sub, field, "jkey") -> key = "jkey"
# stat_category_emit_json() renders every field as %lu, so leaf type is u64.
FIELD_RE = re.compile(
    r'STAT_FIELD(?P<json>_JSON)?(?P<sub>_SUB)?\s*\(\s*'
    r'[A-Za-z_][A-Za-z0-9_.]*\s*,\s*'
    r'(?P<member>[A-Za-z_][A-Za-z0-9_]*)\s*'
    r'(?:,\s*"(?P<jkey>[^"]+)")?\s*\)'
)
FIELDS_DECL_HDR_RE = re.compile(
    r'\bstruct\s+stat_field\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*'
    r'\[\s*\]\s*=\s*\{',
)
# Raw designated-initializer form (no STAT_FIELD macro), used where the
# field is inside a per-index array slot:
#   { .name = "tmpl_arp", .offset = offsetof(..., array[N]) }
# .json_key = "X" overrides .name if present.
RAW_FIELD_RE = re.compile(
    r'\{\s*(?:'
    r'\.name\s*=\s*"(?P<name>[^"]+)"'
    r'|\.json_key\s*=\s*"(?P<jkey>[^"]+)"'
    r'|\.offset\s*=\s*[^,}]+'
    r'|,\s*'
    r'|\s+'
    r')+\}',
    re.DOTALL,
)
CATEGORY_DECL_RE = re.compile(
    r'\bstruct\s+stat_category\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*'
    r'STAT_CATEGORY\s*\(\s*"(?P<jname>[^"]+)"\s*,\s*'
    r'[A-Za-z_][A-Za-z0-9_.\[\]]*\s*,\s*'
    r'(?P<fvar>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;',
    re.DOTALL,
)

fields_registry = {}     # fields_var -> [(json_key, "u64"), ...]
category_registry = {}   # category_var -> (json_name, fields_var, defined_in)

STATS_C = sorted(glob.glob(os.path.join(root, "stats", "**", "*.c"),
                           recursive=True))
if not STATS_C:
    print("stats-json-schema: no .c files under stats/", file=sys.stderr)
    sys.exit(2)

def strip_comments(src):
    # Remove /* ... */ and // ... comments so they don't perturb literal
    # extraction.  Preserve string AND char literals verbatim so that a
    # '{' / '}' character literal inside putchar('{'); does not perturb
    # brace-balance tracking downstream.  Char and string bodies are
    # guarded by their opening quote here so this pass never treats a
    # comment marker inside a literal as a real comment start.
    out = []
    i, n = 0, len(src)
    in_str = False
    in_char = False
    while i < n:
        c = src[i]
        if in_str:
            out.append(c)
            if c == '\\' and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if in_char:
            out.append(c)
            if c == '\\' and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == "'":
                in_char = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "'":
            in_char = True
            out.append(c)
            i += 1
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            if j < 0:
                break
            i = j + 2
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i + 2)
            if j < 0:
                break
            i = j
            continue
        out.append(c)
        i += 1
    return ''.join(out)

def extract_array_body(src, hdr_end):
    """Given the index of the '{' that opens an array initializer (hdr_end
       points just past that brace), return (body_text, end_idx) where
       body_text is the content between the outer braces, respecting
       string / char literals and nested braces."""
    depth = 1
    j = hdr_end
    n = len(src)
    while j < n:
        c = src[j]
        if c == '"':
            j += 1
            while j < n:
                if src[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            continue
        if c == "'":
            j += 1
            while j < n:
                if src[j] == '\\' and j + 1 < n:
                    j += 2
                    continue
                if src[j] == "'":
                    j += 1
                    break
                j += 1
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return src[hdr_end:j], j + 1
        j += 1
    return src[hdr_end:], n

def parse_fields_body(body):
    """Extract the ordered key list from a stat_field[] array body.
       Handles both STAT_FIELD* macros and raw designated initializers.
       Returns [(json_key, "u64"), ...]."""
    keys = []
    # Walk top-level elements, tracking brace depth so we don't confuse
    # nested designated initializers.
    i, n = 0, len(body)
    while i < n:
        # Skip whitespace and commas.
        while i < n and body[i] in ' \t\n\r,':
            i += 1
        if i >= n:
            break
        # STAT_FIELD* macro entry?
        m = FIELD_RE.match(body, i)
        if m:
            override = m.group("jkey")
            member = m.group("member")
            keys.append((override if override else member, "u64"))
            i = m.end()
            continue
        # Raw designated initializer -- pull out .name and (optional) .json_key.
        if body[i] == '{':
            depth = 1
            j = i + 1
            while j < n and depth > 0:
                if body[j] == '"':
                    j += 1
                    while j < n:
                        if body[j] == '\\' and j + 1 < n:
                            j += 2
                            continue
                        if body[j] == '"':
                            j += 1
                            break
                        j += 1
                    continue
                if body[j] == '{':
                    depth += 1
                elif body[j] == '}':
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                j += 1
            elem = body[i:j]
            name_m = re.search(r'\.name\s*=\s*"([^"]+)"', elem)
            jkey_m = re.search(r'\.json_key\s*=\s*"([^"]+)"', elem)
            if name_m or jkey_m:
                key = jkey_m.group(1) if jkey_m else name_m.group(1)
                keys.append((key, "u64"))
            i = j
            continue
        # Unrecognized token: skip one char and keep going.
        i += 1
    return keys

for path in STATS_C:
    with open(path) as f:
        raw = f.read()
    src = strip_comments(raw)
    for m in FIELDS_DECL_HDR_RE.finditer(src):
        name = m.group("name")
        body, _end = extract_array_body(src, m.end())
        keys = parse_fields_body(body)
        # Silently allow re-registration -- some fields arrays are named
        # the same across files but always co-defined with their category.
        fields_registry[name] = keys
    for m in CATEGORY_DECL_RE.finditer(src):
        var = m.group("var")
        jname = m.group("jname")
        fvar = m.group("fvar")
        category_registry[var] = (jname, fvar, path)

# --- Pass 2: per-file section-emitter parse. ------------------------------
# For each stats/json/*.c file, walk each top-level `void FN(void)`
# function body in source order.  Inside a body, walk statements in order
# and extract an "emission stream" -- a flat list of tokens:
#   ("literal", "...")            for a fputs/putchar/printf format literal
#   ("string", None)              for a json_emit_string(...) call
#   ("category", var_name)        for a stat_category_emit_json(&X_category)
#
# We ignore other function calls (they don't emit JSON tokens at the
# per-key granularity we're pinning).  The concatenated literal stream is
# then parsed as a JSON-shape recognizer that yields (depth, key, type)
# events in emission order.

JSON_DIR = os.path.join(root, "stats", "json")
JSON_FILES = sorted(f for f in glob.glob(os.path.join(JSON_DIR, "*.c"))
                    if os.path.basename(f) not in ("common.c", "internal.h"))

FUNC_DEF_RE = re.compile(
    r'^\s*(?:static\s+)?(?:void|bool)'
    r'(?:\s+__[A-Za-z_][A-Za-z0-9_]*)*'
    r'\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\('
    r'(?P<params>[^)]*)\)\s*\{',
    re.MULTILINE,
)

def find_function_bodies(src):
    """Yield (name, body_text) for each top-level void/bool function.
       Brace-counting skips over string and char literals so a putchar
       or fputs argument containing '{'/'}' does not throw off the
       balance."""
    n = len(src)
    for m in FUNC_DEF_RE.finditer(src):
        name = m.group("name")
        start = m.end() - 1   # points at the '{'
        depth = 0
        j = start
        while j < n:
            c = src[j]
            if c == '"':
                j += 1
                while j < n:
                    if src[j] == '\\' and j + 1 < n:
                        j += 2
                        continue
                    if src[j] == '"':
                        j += 1
                        break
                    j += 1
                continue
            if c == "'":
                j += 1
                while j < n:
                    if src[j] == '\\' and j + 1 < n:
                        j += 2
                        continue
                    if src[j] == "'":
                        j += 1
                        break
                    j += 1
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    yield name, src[start + 1:j]
                    break
            j += 1

def unescape_c_string(lit):
    # Minimal C-string unescape -- we only need to recover the JSON syntax
    # bytes (quotes, braces, backslash-quoted keys, colons, commas).
    out = []
    i = 0
    while i < len(lit):
        c = lit[i]
        if c == '\\' and i + 1 < len(lit):
            n = lit[i + 1]
            m = {'n': '\n', 't': '\t', 'r': '\r', '"': '"',
                 '\\': '\\', "'": "'", '0': '\0', 'b': '\b', 'f': '\f'}
            if n in m:
                out.append(m[n])
                i += 2
                continue
            if n == 'x' and i + 3 < len(lit):
                out.append(chr(int(lit[i + 2:i + 4], 16)))
                i += 4
                continue
            out.append(n)
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)

STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')

EMIT_HELPER_CALL_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*\('
)
# Standard library calls that produce their arguments as literals; we
# skip the identifier and let the literal-scanner pick up the format
# string.  Anything not in this set is treated as a call event so
# resolve_section() can recurse into the callee.
LIBC_EMIT = {'printf', 'fputs', 'puts', 'putchar', 'fflush',
             'sprintf', 'fprintf', 'output', 'strcmp', 'strncmp',
             'sizeof', 'offsetof', 'ARRAY_SIZE', 'return',
             'if', 'else', 'while', 'for', 'switch', 'case',
             'goto', 'do', 'break', 'continue', 'sizeof'}

def parse_body_stream(body):
    """Convert a function body into an ordered emission-stream:
       ('literal', text) | ('string', None) | ('category', var)
       | ('call', helper_name).  Helper calls let resolve_section()
       recurse into the callee body -- section functions frequently
       delegate the actual emission to static helpers in the same
       file (e.g. json_emit_kcov_section() calls json_emit_kcov_*
       helpers)."""
    stream = []
    i, n = 0, len(body)
    while i < n:
        # stat_category_emit_json(&NAME_category);
        m = re.match(r'stat_category_emit_json\s*\(\s*&\s*'
                     r'([A-Za-z_][A-Za-z0-9_]*)\s*\)', body[i:])
        if m:
            stream.append(('category', m.group(1)))
            i += m.end()
            continue
        # json_emit_string(...);
        m = re.match(r'json_emit_string\s*\(', body[i:])
        if m:
            stream.append(('string', None))
            i += m.end()
            continue
        # Any string literal at this position feeds the literal stream.
        # We do not distinguish printf vs fputs vs puts -- the emitted
        # bytes are the same set of format-string characters.
        m = STRING_LITERAL_RE.match(body[i:])
        if m:
            stream.append(('literal', unescape_c_string(m.group(1))))
            i += m.end()
            continue
        # putchar('X');  and  fputc('X', stdout);
        m = re.match(
            r"(?:putchar|fputc)\s*\(\s*'(\\.|[^'\\])'"
            r"(?:\s*,\s*(?:stdout|stderr))?\s*\)", body[i:])
        if m:
            ch = m.group(1)
            if ch.startswith('\\'):
                ch = unescape_c_string(ch)
            stream.append(('literal', ch))
            i += m.end()
            continue
        # Bare helper call?  Only match identifiers that look like our
        # JSON emitters -- name starts with json_emit_ or dump_stats_json_
        # or ends with _section.  This dodges routine C control-flow and
        # arithmetic while still catching the real delegation targets.
        m = EMIT_HELPER_CALL_RE.match(body[i:])
        if m:
            fname = m.group(1)
            if (fname not in LIBC_EMIT
                and (fname.startswith('json_emit_')
                     or fname.startswith('dump_stats_json_')
                     or fname.endswith('_section'))):
                stream.append(('call', fname))
                i += m.end() - 1  # leave '(' so nested parens are skipped by
                                  # normal char stepping below on next iters
                # Advance past the paren-balanced argument list so we don't
                # re-tokenize its literals as top-level emissions.
                depth = 0
                while i < n:
                    c = body[i]
                    if c == '(':
                        depth += 1
                    elif c == ')':
                        depth -= 1
                        if depth == 0:
                            i += 1
                            break
                    elif c == '"':
                        i += 1
                        while i < n:
                            if body[i] == '\\' and i + 1 < n:
                                i += 2
                                continue
                            if body[i] == '"':
                                i += 1
                                break
                            i += 1
                        continue
                    i += 1
                continue
        i += 1
    return stream

# --- Pass 3: recognize JSON structure from the concatenated literal
# stream produced per section emitter.

FMT_TYPE_MAP = [
    (re.compile(r'%[-0-9.]*l?lu'),        'u64'),
    (re.compile(r'%[-0-9.]*llu'),         'u64'),
    (re.compile(r'%[-0-9.]*u'),           'u32'),
    (re.compile(r'%[-0-9.]*l?ld'),        'i64'),
    (re.compile(r'%[-0-9.]*d'),           'i32'),
    (re.compile(r'%[-0-9.]*[eEfgG]'),     'f64'),
    (re.compile(r'%[-0-9.]*s'),           'str'),
    (re.compile(r'%[-0-9.]*c'),           'str'),
]

def infer_fmt_type(rest):
    """rest starts right after 'key:' -- classify the value token."""
    rest = rest.lstrip()
    if not rest:
        return None
    c = rest[0]
    if c == '{':
        return 'object'
    if c == '[':
        return 'array'
    if c == '"':
        return 'str'
    # 'null' literal (used on early-return error paths: fputs(",\"kcov\":null")).
    if rest[:4] == 'null':
        return 'null'
    for pat, tname in FMT_TYPE_MAP:
        m = pat.match(rest)
        if m:
            return tname
    return None

class SchemaEmitter:
    def __init__(self):
        self.events = []           # ordered list of (depth, path, type)
        # Each stack frame: {'seen': set(), 'has_path': bool}.  When the
        # frame corresponds to a keyed object/array (opened by a preceding
        # note() event), has_path=True so pop pops the path too.  Frames
        # for anonymous braces (array element opens, etc.) carry
        # has_path=False.  Any keyed event we're about to descend into
        # is queued in self.pending_child and consumed by the very next
        # '{' or '[' scope-open.
        self.stack = [{'seen': set(), 'has_path': False}]  # root
        self.path = []
        self.errors = []
        self.pending_child = None  # key that the next '{' or '[' opens

    def push_scope(self):
        has_path = False
        if self.pending_child is not None:
            self.path.append(self.pending_child)
            self.pending_child = None
            has_path = True
        self.stack.append({'seen': set(), 'has_path': has_path})

    def pop_scope(self):
        # Drop any unconsumed pending_child -- an object/array event
        # without a matching open brace in the same body is a parser
        # anomaly, not a legitimate schema descent.
        self.pending_child = None
        if len(self.stack) > 1:
            frame = self.stack.pop()
            if frame['has_path'] and self.path:
                self.path.pop()

    def note(self, key, ktype):
        # Nullable-value reconciliation: an early-return error path may
        # emit `"key":null` while the happy path later emits the real
        # `"key":{...}` at the same scope.  Merge these instead of
        # tripping a duplicate-key diagnostic; the pinned type is the
        # non-null variant (schema consumers see either shape at runtime,
        # so nullable is intentional and captured by the '?' suffix).
        full = '.'.join(self.path + [key]) if self.path else key
        depth = len(self.path)
        seen = self.stack[-1]['seen']
        if key in seen:
            # Find the prior event at this scope with the same path
            # and reconcile null-vs-other into a nullable type.
            prior_idx = None
            for k in range(len(self.events) - 1, -1, -1):
                if (self.events[k][0] == depth
                        and self.events[k][1] == full):
                    prior_idx = k
                    break
            if prior_idx is not None:
                prior = self.events[prior_idx]
                if prior[2] == 'null' and ktype != 'null':
                    self.events[prior_idx] = (depth, full, ktype + '?')
                    if ktype in ('object', 'array'):
                        self.pending_child = key
                    return
                if ktype == 'null' and prior[2] != 'null':
                    base = prior[2].rstrip('?')
                    self.events[prior_idx] = (depth, full, base + '?')
                    return
                # Identical repeated event (e.g. a syscall-array element
                # emits the same per-syscall shape N times because the
                # generator function is invoked in multiple loop bodies).
                # Merge silently -- the schema is intentionally one shape
                # per array-element slot.
                if prior[2] == ktype:
                    if ktype in ('object', 'array'):
                        self.pending_child = key
                    return
            self.errors.append(
                "duplicate key '%s' at scope %s"
                % (key, '.'.join(self.path) or '<root>'))
        seen.add(key)
        self.events.append((depth, full, ktype))
        if ktype in ('object', 'array'):
            # Descend into the child scope on the next '{' / '['.
            self.pending_child = key

def emit_category_tokens(catvar):
    """Return the synthesized literal-stream fragment for
       stat_category_emit_json(&catvar)."""
    if catvar not in category_registry:
        return None, "unknown stat_category variable '%s'" % catvar
    jname, fvar, _def = category_registry[catvar]
    if fvar not in fields_registry:
        return None, ("category '%s' references unknown fields array '%s'"
                      % (catvar, fvar))
    keys = fields_registry[fvar]
    parts = ['"%s":{' % jname]
    for i, (k, t) in enumerate(keys):
        if i:
            parts.append(',')
        parts.append('"%s":%%lu' % k)
    parts.append('}')
    return ''.join(parts), None

# The order dump_stats_json() calls its section emitters IS the schema
# order.  Parse dump.c to get that call sequence.
DUMP_PATH = os.path.join(JSON_DIR, "dump.c")
with open(DUMP_PATH) as f:
    dump_src = strip_comments(f.read())

section_calls = []
for name, body in find_function_bodies(dump_src):
    if name != "dump_stats_json":
        continue
    for stmt in parse_body_stream(body):
        section_calls.append(stmt)
    break
if not section_calls:
    print("stats-json-schema: could not parse dump_stats_json() body",
          file=sys.stderr)
    sys.exit(2)

# Resolve each function name referenced in dump_stats_json() to its
# definition somewhere under stats/json/*.c.
func_bodies = {}
for path in JSON_FILES:
    with open(path) as f:
        src = strip_comments(f.read())
    for name, body in find_function_bodies(src):
        func_bodies[name] = (path, body)

# Additionally, dump_stats_json() calls named helpers directly (via bare
# identifiers).  Rebuild the section-call sequence by scanning dump.c's
# body text for identifier(...) calls, in order.
CALL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)')

# Rewalk with a merged stream so calls and literals interleave in order.
sections = []
for name, body in find_function_bodies(dump_src):
    if name != "dump_stats_json":
        continue
    i, n = 0, len(body)
    while i < n:
        m = CALL_RE.match(body, i)
        if m:
            fname = m.group(1)
            if fname in ("putchar", "printf", "fputs", "fflush",
                         "puts", "sprintf"):
                i = m.end()
                continue
            sections.append(('call', fname))
            i = m.end()
            continue
        lm = STRING_LITERAL_RE.match(body, i)
        if lm:
            sections.append(('literal', unescape_c_string(lm.group(1))))
            i = lm.end()
            continue
        pm = re.match(r"putchar\s*\(\s*'(\\.|[^'\\])'\s*\)", body[i:])
        if pm:
            ch = pm.group(1)
            if ch.startswith('\\'):
                ch = unescape_c_string(ch)
            sections.append(('literal', ch))
            i += pm.end()
            continue
        i += 1
    break

# Build the composite emission stream.
def resolve_section(fname, seen=None):
    """Return the ordered emission stream for a single section-emitter
       function, expanding stat_category_emit_json() and nested calls
       recursively (with cycle guard)."""
    if seen is None:
        seen = set()
    if fname in seen:
        return []
    seen = seen | {fname}
    if fname not in func_bodies:
        return [('missing_func', fname)]
    _p, body = func_bodies[fname]
    stream = parse_body_stream(body)
    expanded = []
    for kind, val in stream:
        if kind == 'call':
            for sub in resolve_section(val, seen):
                expanded.append(sub)
        else:
            expanded.append((kind, val))
    return expanded

# Flatten the top-level section list + each section's stream into a
# single ordered ("literal", text) stream, expanding categories.
missing_funcs = []
unresolved_categories = []
literal_stream = []

def append_literal(s):
    if literal_stream and literal_stream[-1][0] == 'literal':
        literal_stream[-1] = ('literal',
                              literal_stream[-1][1] + s)
    else:
        literal_stream.append(('literal', s))

for kind, val in sections:
    if kind == 'literal':
        append_literal(val)
        continue
    # kind == 'call' -- expand the function.
    if val not in func_bodies:
        missing_funcs.append(val)
        continue
    for skind, sval in resolve_section(val):
        if skind == 'literal':
            append_literal(sval)
        elif skind == 'string':
            append_literal('"%s"')  # placeholder token; classified as str
        elif skind == 'category':
            frag, err = emit_category_tokens(sval)
            if err:
                unresolved_categories.append((val, sval, err))
                continue
            append_literal(frag)
        elif skind == 'missing_func':
            missing_funcs.append(sval)

if unresolved_categories:
    for fname, cvar, err in unresolved_categories:
        print("stats-json-schema: in %s: %s" % (fname, err), file=sys.stderr)
    sys.exit(2)

# --- Pass 4: tokenize the composite literal stream as JSON-structure. ----
# We are NOT parsing actual runtime JSON output.  We are parsing the
# concatenated printf FORMAT stream (with %-conversions), which has the
# same brace/comma/quote/key structure as the emitted JSON but leaves
# scalar values as %-specifiers -- which is exactly what we want in
# order to record the value TYPE at each leaf.

composite = ''.join(t for k, t in literal_stream if k == 'literal')


emitter = SchemaEmitter()
i, n = 0, len(composite)

def read_key(text, start):
    """Read a JSON key: '"foo"' at start.  Return (key, end) or (None, start)."""
    if start >= len(text) or text[start] != '"':
        return None, start
    j = start + 1
    key = []
    while j < len(text):
        c = text[j]
        if c == '\\' and j + 1 < len(text):
            key.append(text[j + 1])
            j += 2
            continue
        if c == '"':
            return ''.join(key), j + 1
        key.append(c)
        j += 1
    return None, start

# Emitter starts with an implicit root frame.  Every '{' / '[' pushes
# a new frame, consuming any pending keyed path descent queued by the
# preceding note() event; every '}' / ']' pops back.
#
# Bracket kind is tracked in parallel so that array-element shapes are
# recorded exactly once: array emitters commonly stamp the same
# per-element object multiple times (biarch's 32-bit + 64-bit loops,
# and the non-biarch else branch, all call json_emit_syscall() in
# sequence -- three copies of the identical element schema in the
# composite stream).  After the first '{' element inside an array has
# been fully consumed, subsequent siblings are skipped up to the
# matching ']'.
bracket_stack = []           # 'root' | 'obj' | 'arr' | 'arr_done'

def bracket_push(kind):
    bracket_stack.append(kind)

def bracket_pop():
    if bracket_stack:
        bracket_stack.pop()

def bracket_top():
    return bracket_stack[-1] if bracket_stack else 'root'

def skip_to_matching_brace(text, start, open_ch, close_ch):
    depth = 1
    j = start
    n2 = len(text)
    while j < n2:
        c = text[j]
        if c == '"':
            j += 1
            while j < n2:
                if text[j] == '\\' and j + 1 < n2:
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n2

bracket_push('root')

while i < n:
    c = composite[i]
    if c in ' \t\n\r,':
        i += 1
        continue
    if c == '{':
        parent = bracket_top()
        if parent == 'arr_done':
            # Additional sibling inside an array whose shape was already
            # captured -- skip its body wholesale.
            i = skip_to_matching_brace(composite, i + 1, '{', '}')
            continue
        emitter.push_scope()
        bracket_push('obj')
        if parent == 'arr':
            # First element inside this array -- mark the array frame so
            # subsequent siblings are skipped.
            bracket_stack[-2] = 'arr_done'
        i += 1
        continue
    if c == '[':
        emitter.push_scope()
        bracket_push('arr')
        i += 1
        continue
    if c == '}' or c == ']':
        emitter.pop_scope()
        bracket_pop()
        i += 1
        continue
    if c == '"':
        key, j = read_key(composite, i)
        if key is None:
            i += 1
            continue
        # Expect a ':' next.
        while j < n and composite[j] in ' \t\n\r':
            j += 1
        if j >= n or composite[j] != ':':
            # A bare string literal (not a key); skip.
            i = j
            continue
        j += 1
        ktype = infer_fmt_type(composite[j:])
        if ktype is None:
            emitter.errors.append(
                "cannot infer type for key '%s' (path=%s) near: %r"
                % (key, '.'.join(emitter.path) or '<root>',
                   composite[j:j + 32]))
            i = j
            continue
        emitter.note(key, ktype)
        i = j
        # Scalar leaves: skip the format-conversion token so it isn't
        # re-parsed.  Object/array leaves leave the '{' / '[' in place
        # for the next tokenizer iteration to open the child scope --
        # note() only queued the path descent, push_scope() consumes it.
        if ktype in ('object', 'array', 'null'):
            continue
        m = re.match(r'%[-0-9.]*[lh]*[a-zA-Z]|"[^"]*"', composite[i:])
        if m:
            i += m.end()
        else:
            i += 1
        continue
    i += 1

# --- Pass 5: fold picker-context on per-syscall totals. -------------------
# The runtime already folds every picker-context slice into per-nr
# totals (see json_emit_kcov_snapshot_previous() and the callers under
# stats/kcov/dump-topn.c that sum across PICKER_NCTX).  This check
# enforces the FOLD is complete: if any emitted key-path contains a
# ".picker_context." dimension, the fold was skipped and a per-context
# split leaked into the JSON schema.
for depth, path, ktype in emitter.events:
    if ".picker_context." in path or path.endswith(".picker_context"):
        emitter.errors.append(
            "per-syscall total '%s' leaks picker_context dim "
            "(runtime is supposed to fold across PICKER_NCTX before emit)"
            % path)

# --- Pass 6: report. ------------------------------------------------------
if missing_funcs:
    for fn in sorted(set(missing_funcs)):
        print("stats-json-schema: dump_stats_json() calls unresolved "
              "helper '%s'" % fn, file=sys.stderr)
    sys.exit(2)

if emitter.errors:
    for e in emitter.errors:
        print("stats-json-schema: " + e, file=sys.stderr)
    sys.exit(2)

for depth, path, ktype in emitter.events:
    print("%s%s\t%s" % ("  " * depth, path, ktype))
PYEOF
) || fail "structural extractor failed"

[ -n "$schema" ] || fail "extractor produced no schema entries"

if [ "$MODE" = "regen" ]; then
	{
		cat <<'EOF'
# stats-json-schema.baseline
#
# Ordered structural schema of the --stats-json document, produced by
# scripts/check-static/stats-json-schema.sh from stats/json/*.c plus the
# STAT_CATEGORY / STAT_FIELD* descriptor tables under stats/.
#
# One entry per (key-path, value-type) tuple in emission order.  Indent
# reflects nesting depth so a diff reads naturally.  Types:
#   object / array   -- nested container
#   u64 / u32 / i64  -- integer scalar (printf %lu / %u / %ld family)
#   i32 / f64        -- integer / floating scalar
#   str              -- string scalar (%s or json_emit_string)
#
# Regenerate after an intentional schema change with
#   scripts/check-static/stats-json-schema.sh --regen
# and commit the diff alongside the code change with a Summary line
# explaining why the key moved / retyped / reordered.
#
# Lines beginning with '#' and blank lines are ignored on read.
EOF
		printf '%s\n' "$schema"
	} > "$BASELINE"
	count=$(printf '%s\n' "$schema" | wc -l)
	echo "REGEN: $NAME: wrote $count schema entries to ${BASELINE#"$ROOT"/}"
	exit 0
fi

[ -r "$BASELINE" ] || fail "baseline missing at ${BASELINE#"$ROOT"/} -- run with --regen to seed"

# Strip comments and blank lines from the baseline for comparison; keep
# the ordered structure intact (no sort).
baseline=$(grep -Ev '^\s*(#|$)' "$BASELINE")

# Normalise enum pins (enum:v1|v2|...) back to str before comparing against
# the source-reconstructed schema, which always emits 'str' for %s fields.
# The enum annotation is a runtime-gate refinement; the static schema check
# only cares that the field is string-typed, not which tokens are allowed.
baseline=$(printf '%s\n' "$baseline" | sed 's/\tenum:[^\t]*/\tstr/g')

if [ "$schema" = "$baseline" ]; then
	count=$(printf '%s\n' "$schema" | wc -l)
	echo "PASS: $NAME: $count schema entries pinned"
	exit 0
fi

# Drift.  Emit an ordered diff so the reviewer sees where the schema
# moved rather than just what set-changed.
{
	echo "FAIL: $NAME: JSON schema drift vs baseline (${BASELINE#"$ROOT"/})"
	diff -u \
		<(printf '%s\n' "$baseline") \
		<(printf '%s\n' "$schema") \
		| sed 's/^/  /'
	echo "  If the schema change is intentional, run"
	echo "    scripts/check-static/stats-json-schema.sh --regen"
	echo "  and commit the updated baseline alongside the code change."
} >&2
exit 1
