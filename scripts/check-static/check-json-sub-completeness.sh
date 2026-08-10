#!/bin/bash
#
# check-json-sub-completeness: for every struct that is JSON-emitted via a
# stat_category descriptor table (STAT_FIELD_SUB / STAT_FIELD_JSON_SUB rows),
# verify that every scalar (non-array) field of that struct appears in at
# least one descriptor row or bespoke offsetof entry.
#
# Background: both STAT_FIELD_SUB(sub, field) and STAT_FIELD_JSON_SUB(sub,
# field, jkey) register a field for JSON emission via stat_category_emit_json.
# If a field is added to the underlying struct but its descriptor row is
# omitted, check-stats-reachable passes (text-side consumer read counts as
# "reachable") and stats-field-unemitted passes (field name appears in text
# emitter).  Only the JSON output is silently incomplete.  This is the gap
# that let rtnl_ack_oracle.bad_framing slip through until commit t489.
#
# Method:
#  1. From stats/json/**/*.c, collect every field registered via
#     STAT_FIELD_SUB, STAT_FIELD_JSON_SUB, or bespoke offsetof rows.
#  2. For each unique `sub`, resolve the struct type via include/stats.h.
#  3. From stats/subsys/*.h, enumerate every non-array scalar field of
#     that struct type.
#  4. Report any scalar field not in the covered set, not in the static
#     ALLOWLIST (array walkers / internal bookkeeping), and not in the
#     shrinking baseline file of pre-existing gaps.
#
# Pre-existing gaps live in check-json-sub-completeness.baseline.
# That file should shrink over time, never grow.

set -u
export LC_ALL=C

NAME="check-json-sub-completeness"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASELINE="$ROOT/scripts/check-static/check-json-sub-completeness.baseline"

python3 - "$ROOT" "$BASELINE" <<'PYEOF'
import re, sys, os, collections

root, baseline_path = sys.argv[1], sys.argv[2]
NAME = "check-json-sub-completeness"
json_dir = os.path.join(root, "stats", "json")

# Static allowlist: sub.field pairs emitted via bespoke array walkers or
# classified as internal bookkeeping that should not appear in JSON.
# Keep this list narrow; prefer the baseline file for pre-existing gaps.
ALLOWLIST = {
    # rtnl_ack_oracle: type_accepted_per_group[64] walked by the custom
    # per-group emitter in stats/dump/oracle.c; not a scalar descriptor row.
    "rtnl_ack_oracle.type_accepted_per_group",
    # tracefs_fuzzer: forward-carved placeholder; no live producer yet.
    "tracefs_fuzzer.ftrace_subset_skipped",
}

# Load baseline of pre-existing gaps.
baseline = set()
if os.path.isfile(baseline_path):
    with open(baseline_path) as fh:
        for line in fh:
            line = re.sub(r'\s*#.*', '', line).strip()
            if line.startswith("MISSING:"):
                baseline.add(line[len("MISSING:"):].strip())

# Step 1: collect fields covered by descriptor rows in stats/json/**/*.c.
sub_json_re = re.compile(r'STAT_FIELD(?:_JSON)?_SUB\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)')
offset_re   = re.compile(r'offsetof\(\s*struct\s+stats_s\s*,\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)')

covered  = collections.defaultdict(set)   # sub -> {field, ...}
subs_seen = set()

for dirpath, _, fnames in os.walk(json_dir):
    for fname in sorted(fnames):
        if not fname.endswith(".c"):
            continue
        with open(os.path.join(dirpath, fname)) as fh:
            for line in fh:
                for m in sub_json_re.finditer(line):
                    sub, field = m.group(1), m.group(2)
                    covered[sub].add(field)
                    subs_seen.add(sub)
                for m in offset_re.finditer(line):
                    covered[m.group(1)].add(m.group(2))

if not subs_seen:
    print("FAIL: no STAT_FIELD*_SUB rows found -- script broken?", file=sys.stderr)
    sys.exit(1)

# Step 2: resolve sub -> struct_type from include/stats.h.
member_re = re.compile(r'\bstruct\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\b')
sub_to_struct = {}
with open(os.path.join(root, "include", "stats.h")) as fh:
    for line in fh:
        for m in member_re.finditer(line):
            sub_to_struct[m.group(2)] = m.group(1)

# Step 3: enumerate non-array scalar fields per struct from stats/subsys/*.h.
subsys_dir = os.path.join(root, "stats", "subsys")
struct_scalars = collections.defaultdict(list)

struct_open_re = re.compile(r'^\s*struct\s+([A-Za-z_]\w*)\s*\{')
scalar_type_re = re.compile(
    r'^\s*(?:unsigned\s+long(?:\s+long)?|unsigned(?:\s+int)?|uint(?:8|16|32|64)_t)\s+'
    r'([A-Za-z_]\w*)(.*?);')

for fname in sorted(os.listdir(subsys_dir)):
    if not fname.endswith(".h"):
        continue
    cur_struct, depth = None, 0
    with open(os.path.join(subsys_dir, fname)) as fh:
        for line in fh:
            s = re.sub(r'/\*.*?\*/', '', line)
            s = re.sub(r'//.*', '', s)
            if cur_struct is None:
                m = struct_open_re.match(s)
                if m:
                    cur_struct, depth = m.group(1), 1
                continue
            depth += s.count('{') - s.count('}')
            if depth <= 0:
                cur_struct = None
                continue
            m = scalar_type_re.match(s)
            if m and '[' not in m.group(2):
                struct_scalars[cur_struct].append(m.group(1))

# Step 4: detect gaps.
gaps = []
seen_in_baseline = set()
stale_baseline = []

for sub in sorted(subs_seen):
    struct_type = sub_to_struct.get(sub)
    if not struct_type:
        continue
    for field in struct_scalars.get(struct_type, []):
        key = sub + "." + field
        if field in covered[sub] or key in ALLOWLIST:
            continue
        if key in baseline:
            seen_in_baseline.add(key)
        else:
            gaps.append((sub, struct_type, field))

for key in baseline:
    if key not in seen_in_baseline:
        stale_baseline.append(key)

rc = 0
if stale_baseline:
    print("FAIL: %s: stale baseline entries (field now covered or removed):" % NAME, file=sys.stderr)
    for k in sorted(stale_baseline):
        print("  MISSING:%s" % k, file=sys.stderr)
    print("Remove these from %s" % baseline_path, file=sys.stderr)
    rc = 1

if gaps:
    print("FAIL: %s: new scalar field(s) missing from JSON descriptor table:" % NAME, file=sys.stderr)
    for sub, stype, field in gaps:
        print("  %s.%s  (struct %s)" % (sub, field, stype), file=sys.stderr)
    print("", file=sys.stderr)
    print("Fix: add STAT_FIELD_SUB(%s, %s) or STAT_FIELD_JSON_SUB(%s, %s, \"%s\")" % (
          gaps[0][0], gaps[0][2], gaps[0][0], gaps[0][2], gaps[0][2]), file=sys.stderr)
    print("     to the descriptor table in stats/json/; or, if intentionally", file=sys.stderr)
    print("     omitted, add MISSING:%s.%s to %s with a reason." % (
          gaps[0][0], gaps[0][2], os.path.basename(baseline_path)), file=sys.stderr)
    rc = 1

if rc == 0:
    total = sum(len(struct_scalars.get(sub_to_struct.get(s,""), [])) for s in subs_seen)
    baselined_n = len(seen_in_baseline)
    print("PASS: %s: %d struct(s), %d scalar field(s) covered (%d baselined)" % (
          NAME, len(subs_seen), total, baselined_n))
sys.exit(rc)
PYEOF
