#!/bin/bash
#
# stats-rotation-jsonl-schema: pin the field names of the rotation-event
# JSONL records against stats-rotation-jsonl-schema.baseline.
#
# stats/rotation_event.c writes the rotation record from one snprintf()
# format string in stats_rotation_event_emit() and the end-of-run record as
# a plain literal in stats_rotation_event_close(), so a field added to or
# dropped from either reshapes the stream with no compile or test failure.
# The "key": names are read out of both and diffed against the [rotation]
# and [terminal] baseline sections in both directions.  Trinity's output is
# never consulted; the live records are cross-checked against the same
# baseline by the opt-in scripts/check-runtime-json-output.sh.
#
# To regenerate after an intentional field change:
#   scripts/check-static/stats-rotation-jsonl-schema.sh --regen
# then review the baseline diff and commit it with the code change.

set -u

NAME="stats-rotation-jsonl-schema"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SOURCE="$ROOT/stats/rotation_event.c"
BASELINE="$ROOT/scripts/check-static/stats-rotation-jsonl-schema.baseline"

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

python3 - "$SOURCE" "$BASELINE" "$MODE" "$NAME" "$ROOT" <<'PYEOF'
import os
import re
import sys

source_path, baseline_path, mode, name, root = sys.argv[1:6]
baseline_rel = os.path.relpath(baseline_path, root)


def fail(msg):
    print(f"FAIL: {name}: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_sections(path):
    sections = {}
    current = None
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            if line.startswith('[') and line.endswith(']'):
                current = line[1:-1]
                sections[current] = []
            elif current is not None:
                sections[current].append(line)
    return sections


def literal_keys(text):
    # In the C source every field appears as \"KEY\":.
    return sorted(set(re.findall(r'\\"([A-Za-z_][A-Za-z0-9_]*)\\":', text)))


with open(source_path) as f:
    src = f.read()

# An extractor that stops finding a record or its keys must fail, not pass
# on an empty set.
#
# [rotation]: the snprintf() call in stats_rotation_event_emit().
call = re.search(r'n\s*=\s*snprintf\s*\(buf[^;]+;', src, re.DOTALL)
if not call:
    fail("could not locate the snprintf call in stats_rotation_event_emit()")

# [terminal]: the literal stats_rotation_event_close() hands to jsonl_write().
# The terminal record contains only {"type":"terminal"} -- a single-field
# sentinel so a downstream reader can distinguish a clean end-of-run from a
# mid-run sink death (where the truncation marker ends the stream).
close = re.search(r'stats_rotation_event_close\s*\(void\)\s*\{(.*?)\n\}',
                  src, re.DOTALL)
literal = close and re.search(
    r'jsonl_write\s*\(\s*rotation_event_fd\s*,\s*"((?:[^"\\]|\\.)*)"',
    close.group(1))
if not literal:
    fail("could not locate the terminal record literal in "
         "stats_rotation_event_close()")

fields = {
    "rotation": literal_keys(call.group(0)),
    "terminal": literal_keys(literal.group(1)),
}
for section, keys in fields.items():
    if not keys:
        fail(f"no field names found for [{section}] in the source")

if mode == "regen":
    lines = [
        "# stats-rotation-jsonl-schema.baseline",
        "#",
        "# Field names for rotation-event JSONL records emitted by",
        "# stats/rotation_event.c: [rotation] from the snprintf format string",
        "# in stats_rotation_event_emit(), [terminal] from the end-of-run",
        "# literal in stats_rotation_event_close().  A quick dry-run rarely",
        "# produces live rotation events, so both come from the source.",
        "#",
        "# Regenerate after a field-name change with:",
        "#   scripts/check-static/stats-rotation-jsonl-schema.sh --regen",
        "# and commit the diff alongside the code change.",
        "",
        "[rotation]",
        *fields["rotation"],
        "",
        "[terminal]",
        *fields["terminal"],
        "",
    ]
    with open(baseline_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"REGEN: {name}: wrote {len(fields['rotation'])} rotation and "
          f"{len(fields['terminal'])} terminal fields to {baseline_rel}")
    sys.exit(0)

if not os.path.exists(baseline_path):
    fail(f"baseline missing at {baseline_rel} -- run with --regen to seed")

sections = parse_sections(baseline_path)
problems = []
for section, keys in fields.items():
    source = set(keys)
    baseline = set(sections.get(section, []))
    added = ", ".join(sorted(source - baseline))
    removed = ", ".join(sorted(baseline - source))
    if added:
        problems.append(f"[{section}] source fields not in the baseline "
                        f"(new field?): {added}")
    if removed:
        problems.append(f"[{section}] baseline fields not in the source "
                        f"(removed field?): {removed}")
if problems:
    print(f"FAIL: {name}: rotation-event fields drifted from {baseline_rel}",
          file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    print("  If the change is intentional, run", file=sys.stderr)
    print("    scripts/check-static/stats-rotation-jsonl-schema.sh --regen",
          file=sys.stderr)
    print("  and commit the updated baseline alongside the code change.",
          file=sys.stderr)
    sys.exit(1)

print(f"PASS: {name}: {len(fields['rotation'])} rotation and "
      f"{len(fields['terminal'])} terminal fields pinned")
PYEOF
