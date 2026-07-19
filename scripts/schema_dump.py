#!/usr/bin/env python3
"""Extract stat_category -> [field_name...] map from source files.

Walks stats/**/*.c looking for `static const struct stat_field NAME[] = { ... };`
followed by a matching `const struct stat_category NAME_category = STAT_CATEGORY(...)`.

Field names come from either:
  - STAT_FIELD*(anything, IDENT)  -> "IDENT"
  - { .name = "STRING", ... }     -> "STRING"

Both are legitimate ways this codebase populates a stat_field slot.
"""
import os
import re
import sys
import glob
import json

FIELD_ARRAY_START = re.compile(
    r'static\s+const\s+struct\s+stat_field\s+([A-Za-z0-9_]+)\s*\[\s*\]\s*=\s*\{',
)
CATEGORY_DEF = re.compile(
    r'const\s+struct\s+stat_category\s+([A-Za-z0-9_]+_category)\s*=\s*'
    r'STAT_CATEGORY\s*\(\s*"([^"]+)"\s*,\s*([A-Za-z0-9_.]+)\s*,\s*([A-Za-z0-9_]+)\s*\)',
    re.DOTALL,
)
STAT_FIELD_MACRO = re.compile(
    r'STAT_FIELD(?:_SUB|_JSON_SUB|_JSON)?\s*\(\s*[A-Za-z0-9_]+\s*,\s*([A-Za-z0-9_]+)',
)
NAME_INIT = re.compile(r'\.name\s*=\s*"([^"]+)"')


def read_array_body(src, start_brace_idx):
    """Return (body, end_idx) — body is text between matching braces."""
    depth = 1
    i = start_brace_idx + 1
    while i < len(src) and depth > 0:
        c = src[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        i += 1
    return src[start_brace_idx + 1:i - 1], i


def extract_fields_from_body(body):
    """Preserve source order: walk the body, matching macros or .name inits."""
    fields = []
    i = 0
    while i < len(body):
        m1 = STAT_FIELD_MACRO.match(body, i)
        m2 = NAME_INIT.match(body, i)
        if m1 and (not m2 or m1.start() < m2.start()):
            pass
        m1_next = STAT_FIELD_MACRO.search(body, i)
        m2_next = NAME_INIT.search(body, i)
        candidates = [m for m in (m1_next, m2_next) if m]
        if not candidates:
            break
        first = min(candidates, key=lambda m: m.start())
        fields.append(first.group(1))
        i = first.end()
    return fields


def extract(root):
    schema = {}
    files = sorted(glob.glob(os.path.join(root, "stats/**/*.c"), recursive=True))
    for path in files:
        with open(path) as f:
            src = f.read()
        arrays = {}
        for m in FIELD_ARRAY_START.finditer(src):
            name = m.group(1)
            brace_idx = m.end() - 1
            body, _ = read_array_body(src, brace_idx)
            arrays[name] = extract_fields_from_body(body)
        for m in CATEGORY_DEF.finditer(src):
            var, cat_name, gate, arr = m.group(1), m.group(2), m.group(3), m.group(4)
            fields = arrays.get(arr, [])
            schema[cat_name] = {
                "var": var,
                "gate": gate,
                "fields": fields,
                "file": os.path.relpath(path, root),
            }
    return schema


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    schema = extract(root)
    print(json.dumps(schema, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
