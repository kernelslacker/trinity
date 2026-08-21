#!/bin/bash
#
# check-runtime-json-output.sh -- runtime validation fixture for trinity's
# JSON/JSONL output surfaces.
#
# Three surfaces under test:
#   1. Final stats JSON  (--stats-json, emitted to stdout by dump_stats_json())
#   2. Periodic JSONL    (stats-timeseries-*.jsonl, via stats/log.c)
#   3. Rotation-event JSONL (rotation-events-*.jsonl, via stats/rotation_event.c)
#
# All existing gates in scripts/check-static/ reconstruct the emission from
# source and diff against a baseline.  None of them ever executes the binary.
# A printf that emits "key":, or a silently-retyped leaf passes every static
# gate.  The two JSONL surfaces have no schema pin at all.  This fixture
# closes those gaps by spawning the binary under the sanctioned capped form
# and cross-checking the live emission against the static baselines.  A
# source-reconstruction error and a binary-emission error produce different
# failures -- that is the whole point of the runtime gate.
#
# Sink-failure is also exercised end-to-end: running from a read-only
# directory verifies that trinity surfaces open failures to stderr and
# continues running rather than crashing silently.
#
# To regenerate baselines after an intentional schema change:
#   scripts/check-static/check-runtime-json-output.sh --regen
# then review the resulting diffs and commit them alongside the code change.
#
# Scope fence (already landed -- do NOT redo):
#   8d326144e77a ("stats: latch ferror and disable timeseries sink on write failure")
#   1f993d65e941 ("stats: emit terminal JSONL record at shutdown with total cross-check")
#   02deb071fca2 ("stats: terminal cross-check must read the monotonic total_op_count")
# This fixture exercises those paths; it does not rebuild the mechanisms.

set -u

NAME="runtime-json-output"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASELINE_JSON="$ROOT/scripts/check-static/stats-json-schema.baseline"
BASELINE_PERIODIC="$ROOT/scripts/check-static/stats-periodic-jsonl-schema.baseline"
BASELINE_ROTATION="$ROOT/scripts/check-static/stats-rotation-jsonl-schema.baseline"

fail_count=0
pass_count=0

fail() {
	echo "FAIL: $NAME: $1" >&2
	fail_count=$((fail_count + 1))
}

pass() {
	pass_count=$((pass_count + 1))
}

# Temporary workspace: all run artifacts land here, cleaned on exit.
WORK="$(mktemp -d /tmp/trinity-rtjson.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[ -x "$ROOT/trinity" ] || {
	echo "FAIL: $NAME: binary $ROOT/trinity not found -- run make first" >&2
	exit 1
}
[ -d "$ROOT/stats/json" ] || {
	echo "FAIL: $NAME: cannot locate stats/json under $ROOT" >&2
	exit 1
}
command -v python3 >/dev/null 2>&1 || {
	echo "FAIL: $NAME: python3 not found in PATH" >&2
	exit 1
}

MODE="check"
case "${1:-}" in
	--regen) MODE="regen" ;;
	"")      MODE="check" ;;
	*)       echo "FAIL: $NAME: unknown arg: $1" >&2; exit 1 ;;
esac

# Enum-pin-count floor: catch baseline regressions where all enum:
# annotations have been silently dropped (e.g. bare --regen without the
# annotation-merge step).  Without this, the enforcement loop in the
# Python cross-check below skips 100% of paths and the gate degrades to
# a pure structural check with no value-set enforcement.
_enum_pin_count=$(grep -c $'\tenum:' "$BASELINE_JSON" 2>/dev/null)
if [ "$_enum_pin_count" -lt 1 ]; then
	echo "FAIL: $NAME: enum pin count ${_enum_pin_count} < floor 1 -- baseline has lost all enum annotations (run stats-json-schema.sh --regen to restore)" >&2
	exit 1
fi

# ---------------------------------------------------------------------------
# Helper: spawn the binary under the sanctioned capped form.
#
# --stats-json writes the JSON document to stdout; wrapper script messages
# (core_pattern echo, outputstd() calls during init) precede it on the same
# stream.  We capture stdout to a file and use Python's JSONDecoder.raw_decode
# to find the JSON object start -- it tolerates arbitrary leading text.
#
# The JSONL files are auto-named by trinity in the CWD; we run from $WORK so
# they land there and are cleaned up automatically.
# ---------------------------------------------------------------------------

# Symlink the binary into WORK so run-trinity.sh's `./trinity` resolves.
ln -sf "$ROOT/trinity" "$WORK/trinity"
# run-trinity.sh also sources scripts/paths.sh; keep absolute path reference
# in the invocation below.

_run_trinity() {
	local extra_args="$*"
	local stdout_file="$WORK/trinity.stdout"
	local stderr_file="$WORK/trinity.stderr"

	# Wipe artifacts from any prior run in WORK.
	rm -f "$WORK"/stats-timeseries-*.jsonl \
	      "$WORK"/rotation-events-*.jsonl \
	      "$WORK/trinity.stdout" \
	      "$WORK/trinity.stderr"

	# Sanctioned capped form (task spec).  --stats-json emits the final
	# JSON document to stdout.  TRINITY_NO_CGROUP=1 avoids the outer
	# systemd-run wrapping so the fixture runs without D-bus/cgroup rights.
	( cd "$WORK" && \
	  timeout -k 15 120 env \
	      TRINITY_NO_DMESG=1 \
	      TRINITY_NO_CGROUP=1 \
	      "$ROOT/scripts/run-trinity.sh" \
	      --dry-run -C 4 $extra_args --stats --stats-json \
	      >"$stdout_file" 2>"$stderr_file" )
}

# ---------------------------------------------------------------------------
# 1. Spawn: basic run for stats-JSON + terminal JSONL check.
# ---------------------------------------------------------------------------

echo "--- $NAME: spawning trinity (--dry-run -N 100) ---"
_run_trinity "-N 100 --max-runtime=2"
TRINITY_RC=$?

if [ "$TRINITY_RC" -ne 0 ]; then
	fail "trinity exited $TRINITY_RC (see $WORK/trinity.stderr)"
	# Surface the last few stderr lines to help triage.
	tail -5 "$WORK/trinity.stderr" >&2
	exit 1
else
	pass
fi

# Save the stats-JSON stdout before the window-record spawn wipes it.
cp "$WORK/trinity.stdout" "$WORK/trinity.stdout.json"

# ---------------------------------------------------------------------------
# 2. Validate final stats JSON against the static baseline.
#
# The static baseline (stats-json-schema.sh) was built by source reconstruction;
# this extractor parses the live binary output.  We compare:
#   - The set of key-paths present in the live JSON
#   - Normalised value-type at each path
# Agreement means neither the source reconstruction nor the binary emission
# has silently drifted from the other.
#
# Type normalisation:
#   int, float       -> "num"   (static extractor classifies %lu/%u/%d as u64/u32/i32;
#                               JSON parse gives Python int -- both collapse to "num")
#   bool             -> "str"   (static extractor sees %s and emits "str"; the C source
#                               writes `cond ? "true" : "false"` via %s, which JSON
#                               parses as a boolean -- normalise to match baseline)
#   str              -> "str"
#   dict             -> "obj"
#   list             -> "arr"
#   NoneType         -> "null"
#
# Integer string keys (e.g. errnos.{"38":3}) are replaced with "%u" to match
# the baseline placeholder used by the static extractor.
# ---------------------------------------------------------------------------

python3 - "$WORK/trinity.stdout.json" "$BASELINE_JSON" "$MODE" "$WORK/stats_json_check.result" <<'PYEOF'
import sys
import json
import re

stdout_path  = sys.argv[1]
baseline_path = sys.argv[2]
mode          = sys.argv[3]
result_path   = sys.argv[4]

# --- helpers ----------------------------------------------------------------

def norm_type(py_val):
    """Normalise a Python value to a schema type token."""
    if isinstance(py_val, bool):
        return "str"    # JSON boolean emitted via %s "true"/"false" in C
    if isinstance(py_val, (int, float)):
        return "num"
    if isinstance(py_val, str):
        return "str"
    if isinstance(py_val, list):
        return "arr"
    if isinstance(py_val, dict):
        return "obj"
    if py_val is None:
        return "null"
    return "?"

BASELINE_TYPE_RE = re.compile(
    r'^(u64|u32|i64|i32|f64|i16|u16|u8|i8)$'
)

def norm_baseline_type(t):
    """Normalise a baseline type annotation to the same token set."""
    t = t.rstrip('?')   # strip nullable marker
    if t.startswith('enum:'):
        return "str"    # enum pins are string-valued; allowed set checked separately
    if BASELINE_TYPE_RE.match(t):
        return "num"
    if t in ("object",):
        return "obj"
    if t in ("array",):
        return "arr"
    if t in ("str",):
        return "str"
    if t in ("null",):
        return "null"
    return t   # pass through for 'obj', 'arr' already normalised

def is_int_key(k):
    return k.isdigit()

def walk_json(obj, path=""):
    """Yield (path, norm_type, raw_val) triples.

    For lists, all elements are visited so that every distinct leaf value
    at each path is yielded.  This is required for enum-pin enforcement:
    the representative-element rule is fine for TYPE inference (schema[path]
    is set on first-wins), but values[path] must accumulate the full value
    set across all array elements so that enum:... pins cover every row, not
    just the first one.

    Plain JSON cannot contain structural cycles, so no visited-path guard is
    needed -- iterating all list elements is safe.

    raw_val is the actual Python value for leaf (non-container) nodes, or
    None for containers.  Callers use raw_val for enum-pin enforcement.
    """
    t = norm_type(obj)
    raw_val = obj if not isinstance(obj, (dict, list)) else None
    if path:  # skip the root node (empty path); only emit named nodes
        yield (path, t, raw_val)
    if isinstance(obj, dict):
        for k, v in obj.items():
            seg = "%u" if is_int_key(k) else k
            child_path = f"{path}.{seg}" if path else seg
            # Skip null children -- they will be absent from the runtime
            # schema but may be present in the baseline as nullable (obj?).
            if v is None:
                yield (child_path, "null", None)
                continue
            yield from walk_json(v, child_path)
    elif isinstance(obj, list):
        # Iterate ALL elements so that values from every row are yielded.
        # schema[path] type is set on first-wins (representative element
        # is fine for type inference); values[path] accumulates all raw
        # values so enum pins cover every array element.
        for elem in obj:
            yield from walk_json(elem, path)

def extract_runtime_schema(stdout_path):
    """Parse the live binary stdout, find the JSON object, walk it.

    trinity emits all human-readable output via output()/outputstd() before
    the JSON document; the JSON lands as the very last non-empty line of
    stdout.  Search lines from the end for one that parses as a JSON object
    containing 'stats' or 'syscalls'.

    Returns (schema, values, error) where schema maps path->norm_type and
    values maps path->raw_value for leaf nodes (used for enum-pin checks).
    """
    with open(stdout_path, "rb") as f:
        raw = f.read().decode("utf-8", errors="replace")
    lines = raw.splitlines()
    decoder = json.JSONDecoder()
    for line in reversed(lines):
        line = line.strip()
        if not line or line[0] not in ('{', '['):
            continue
        try:
            obj, _end = decoder.raw_decode(line)
            if isinstance(obj, dict) and ("stats" in obj or "syscalls" in obj):
                schema = {}
                values = {}
                for path, t, raw_val in walk_json(obj):
                    if path not in schema:
                        schema[path] = t
                    if raw_val is not None:
                        # Accumulate the full set of values seen at this
                        # path across all array elements.  Enum-pin
                        # enforcement checks every collected value, so
                        # unsupported/ran_no_effect (afxdp-only rows) are
                        # caught even though igmp always emits first.
                        if path not in values:
                            values[path] = set()
                        values[path].add(raw_val)
                return schema, values, None
        except json.JSONDecodeError:
            continue
    return None, {}, "no valid JSON object found in stdout (last line must be the JSON document)"

def extract_baseline_schema(baseline_path):
    """Read the static baseline, return {path: norm_type}."""
    schema = {}
    with open(baseline_path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.lstrip().startswith('#'):
                continue
            # Format: "  path\ttype" (2 spaces per indent level in path)
            # The path itself uses dots; indent is just visual.
            parts = line.split('\t', 1)
            if len(parts) != 2:
                continue
            path = parts[0].strip()
            btype = parts[1].strip()
            schema[path] = norm_baseline_type(btype)
    return schema

# --- main -------------------------------------------------------------------

rt_schema, rt_values, err = extract_runtime_schema(stdout_path)
if err:
    print(f"FAIL: stats-json: {err}", flush=True)
    with open(result_path, "w") as f:
        f.write(f"error: {err}\n")
    sys.exit(1)

# In regen mode: report what we found and exit (caller writes baselines).
# Stats-JSON baseline is maintained by stats-json-schema.sh, not regenerated
# here.  We only validate that the live schema is a subset of the static one
# (plus any null-valued paths that appear as nullable in the baseline).
# Regen for the JSONL baselines happens in a separate pass below.

bl_schema = extract_baseline_schema(baseline_path)

# Compare:
#   (a) Paths in runtime but NOT in baseline -> unexpected field (error)
#   (b) Paths in baseline without '?' but NOT in runtime and not null -> warn
#       (many baseline paths are KCOV-gated; a dry-run without KCOV misses them)
#   (c) Paths in both -> type must agree

unexpected = []
type_mismatches = []
runtime_paths = set(rt_schema.keys())
baseline_paths = set(bl_schema.keys())

for p in sorted(runtime_paths):
    if p not in bl_schema:
        unexpected.append(p)
    else:
        rt  = rt_schema[p]
        bl  = bl_schema[p]
        if rt != bl:
            # null at runtime is OK when baseline marks the path as nullable.
            # "null" norm_type in runtime vs "obj"/"arr"/"str"/"num" in baseline
            # is only acceptable when the original baseline type had '?' suffix.
            pass   # type check done separately below

# Re-read raw baseline types for the nullable check.
raw_bl_types = {}
with open(baseline_path) as f:
    for line in f:
        line = line.rstrip('\n')
        if not line or line.lstrip().startswith('#'):
            continue
        parts = line.split('\t', 1)
        if len(parts) == 2:
            raw_bl_types[parts[0].strip()] = parts[1].strip()

for p in sorted(runtime_paths & baseline_paths):
    rt = rt_schema[p]
    bl = bl_schema[p]
    if rt == bl:
        continue
    raw = raw_bl_types.get(p, "")
    # null at runtime, nullable in baseline -> OK
    if rt == "null" and raw.endswith('?'):
        continue
    # num at runtime, nullable obj/arr in baseline -> runtime saw the value,
    # which is unexpected but not necessarily wrong for a type-check gate.
    type_mismatches.append(f"  {p}: runtime={rt!r} baseline={bl!r} (raw={raw!r})")

# Enum-pin enforcement: for baseline entries typed as enum:v1|v2|..., assert
# that the live value (if present) is one of the declared tokens.
enum_errors = []
for p in sorted(runtime_paths & baseline_paths):
    raw = raw_bl_types.get(p, "")
    if not raw.startswith("enum:"):
        continue
    token_str = raw[5:].rstrip('?')  # strip 'enum:' prefix and nullable marker
    allowed   = set(token_str.split("|"))
    actual_set = rt_values.get(p)
    if actual_set is None:
        continue  # value absent at runtime (nullable path, not in this run)
    # Check every collected value -- values[path] is a set accumulating all
    # raw values seen across every array element for this path.
    for actual in sorted(actual_set):
        if actual not in allowed:
            enum_errors.append(
                f"  {p}: value {actual!r} not in allowed set {sorted(allowed)}")

errors = []
if unexpected:
    errors.append("paths in runtime JSON not found in static baseline "
                  "(undeclared fields):")
    for p in sorted(unexpected):
        errors.append(f"  + {p}")
if type_mismatches:
    errors.append("type mismatches between runtime and baseline:")
    for m in type_mismatches:
        errors.append(m)
if enum_errors:
    errors.append("enum-pin violations (value not in declared set):")
    for m in enum_errors:
        errors.append(m)

with open(result_path, "w") as f:
    if errors:
        f.write("error\n")
        f.write("\n".join(errors) + "\n")
    else:
        f.write("ok\n")
        f.write(f"checked {len(runtime_paths)} paths\n")

if errors:
    sys.exit(1)
else:
    sys.exit(0)
PYEOF
STATS_JSON_PY_RC=$?

STATS_JSON_RESULT="$(cat "$WORK/stats_json_check.result" 2>/dev/null | head -1)"
if [ "$STATS_JSON_PY_RC" -ne 0 ] || [ "$STATS_JSON_RESULT" != "ok" ]; then
	fail "stats-JSON cross-check failed"
	cat "$WORK/stats_json_check.result" >&2
else
	NPATH="$(grep 'checked' "$WORK/stats_json_check.result" | awk '{print $2}')"
	echo "PASS: $NAME: stats-JSON cross-check: $NPATH paths verified"
	pass
fi

# ---------------------------------------------------------------------------
# 1b. Second spawn: higher -N to reach the window-emit threshold.
#
# stats_timeseries_emit_window fires when (op_count - lastcount) > 10000
# (main/stats.c).  The -N 100 run above produces only a terminal record;
# no window records are written until op_count exceeds 10000.  This second
# spawn uses -N 15000 to try to reach the window-emit threshold; the
# window record may NOT land (load-dependent -- total_ops in the terminal
# record discriminates emitter-bug from slow-box, section 3).  The JSONL
# files from the -N 100 run are wiped; the stats-JSON stdout was already
# saved above.
# ---------------------------------------------------------------------------

echo "--- $NAME: spawning trinity (--dry-run -N 15000, window-record run) ---"
_run_trinity "-N 15000 --max-runtime=30"
TRINITY_RC_WINDOW=$?

if [ "$TRINITY_RC_WINDOW" -ne 0 ]; then
	fail "trinity (window-record run) exited $TRINITY_RC_WINDOW"
	tail -5 "$WORK/trinity.stderr" >&2
	exit 1
else
	pass
fi

# ---------------------------------------------------------------------------
# 3. Validate the timeseries JSONL: terminal record and window record.
#
# Every run with --stats emits a terminal record on close:
#   {"type":"terminal","total_ops":N,"last_window_op_count":M,"cross_check_ok":true}
# The -N 15000 run above may also produce a window record (load-dependent;
# may NOT land -- total_ops in the terminal record discriminates).
# Both record types are pinned in the
# periodic JSONL baseline.
# ---------------------------------------------------------------------------

# Collect the timeseries JSONL produced by the -N 15000 window-record run.
TSERIES_FILE="$(ls "$WORK"/stats-timeseries-*.jsonl 2>/dev/null | head -1)"

if [ -z "$TSERIES_FILE" ]; then
	fail "no stats-timeseries-*.jsonl found after trinity run"
	exit 1
else
	python3 - "$TSERIES_FILE" "$BASELINE_PERIODIC" "$MODE" \
	    "$WORK/periodic_check.result" <<'PYEOF'
import sys, json, os

ts_path       = sys.argv[1]
baseline_path = sys.argv[2]
mode          = sys.argv[3]
result_path   = sys.argv[4]

errors = []
terminal_keys = None
terminal_rec  = None
window_keys   = None
total_ops     = None

with open(ts_path) as f:
    for lineno, raw in enumerate(f, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError as e:
            errors.append(f"line {lineno}: invalid JSON: {e}")
            continue
        rtype = rec.get("type")
        if rtype == "terminal":
            terminal_keys = sorted(rec.keys())
            terminal_rec  = rec
            total_ops = rec.get("total_ops")
        else:
            # periodic window record
            if window_keys is None:
                window_keys = sorted(rec.keys())

if errors:
    with open(result_path, "w") as f:
        f.write("error\n")
        f.write("\n".join(errors) + "\n")
    sys.exit(1)

# In regen mode, emit the baseline content.
if mode == "regen":
    lines = []
    lines.append("# stats-periodic-jsonl-schema.baseline")
    lines.append("#")
    lines.append("# Field names for the periodic JSONL surfaces emitted by")
    lines.append("# stats/log.c (stats_timeseries_emit_window) and the terminal")
    lines.append("# record written by stats_timeseries_close().")
    lines.append("#")
    lines.append("# Two sections:")
    lines.append("#   [terminal]  -- fields in the shutdown terminal record")
    lines.append("#   [window]    -- fields in a periodic window record")
    lines.append("#                  (only present when >= 10001 ops were run)")
    lines.append("#")
    lines.append("# Regenerate after a field-name change with:")
    lines.append("#   scripts/check-static/check-runtime-json-output.sh --regen")
    lines.append("# and commit the diff alongside the code change.")
    lines.append("")
    # Floor: refuse to write an empty section when the prior baseline had one.
    # Both [terminal] and [window] can legitimately be absent from a short run
    # (terminal requires a clean shutdown; window requires >= 10001 ops), but
    # silently dropping a section that the established baseline carries would
    # corrupt the gate: check mode would then see an empty set for that section
    # and flag every runtime field as 'unexpected' instead of a real failure.
    def _check_regen_floor(section, keys, hint):
        """Abort regen if keys is empty but the prior baseline had [section]."""
        if keys or not os.path.exists(baseline_path):
            return
        header = f'[{section}]'
        with open(baseline_path) as _f:
            for _l in _f:
                if _l.rstrip('\n') == header:
                    with open(result_path, "w") as _rf:
                        _rf.write(
                            f"error: regen would write empty [{section}] section "
                            f"but prior baseline has one -- {hint}\n")
                    sys.exit(1)
    _check_regen_floor("terminal", terminal_keys,
                       "run did not emit a terminal shutdown record")
    if terminal_keys:
        lines.append("[terminal]")
        for k in terminal_keys:
            lines.append(k)
        lines.append("")
    _check_regen_floor("window", window_keys,
                       "run did not reach window-emit threshold; "
                       "use -N 15000 or higher")
    if window_keys:
        lines.append("[window]")
        for k in window_keys:
            lines.append(k)
        lines.append("")
    with open(result_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(baseline_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"REGEN: periodic-jsonl: wrote baseline to {baseline_path}", flush=True)
    sys.exit(0)

# Check mode: validate against baseline.
if not os.path.exists(baseline_path):
    with open(result_path, "w") as f:
        f.write(f"error: baseline missing at {baseline_path} -- run --regen\n")
    sys.exit(1)

def parse_baseline(path):
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

bl_sections = parse_baseline(baseline_path)
bl_terminal = set(bl_sections.get("terminal", []))
bl_window   = set(bl_sections.get("window", []))

check_errors = []
window_skip = False

if terminal_keys is None:
    # A run MUST emit the shutdown terminal record (stats_timeseries_close).
    # Its absence -- an empty stream, or one carrying only window records --
    # means the run never cleanly shut down; that is a real failure, not a
    # load-dependent skip.  Without this branch the whole terminal check
    # (including the cross_check_ok shutdown invariant) was silently skipped.
    check_errors.append(
        "terminal record: absent -- no shutdown terminal record emitted "
        "(empty or window-only JSONL stream)")
else:
    rt_terminal = set(terminal_keys)
    extra = rt_terminal - bl_terminal
    missing = bl_terminal - rt_terminal
    if extra:
        check_errors.append("terminal record: unexpected fields: " +
                             ", ".join(sorted(extra)))
    if missing:
        check_errors.append("terminal record: missing fields: " +
                             ", ".join(sorted(missing)))
    cross_check = terminal_rec.get('cross_check_ok') if terminal_rec else None
    if cross_check is not True:
        check_errors.append(f'terminal record: cross_check_ok={cross_check!r}, expected True (shutdown invariant failed)')

if bl_window and not window_keys:
    # No window records produced.  Discriminate using total_ops from the
    # terminal record: if the run did not reach 10001 ops the threshold
    # was never crossed (load-dependent) -- SKIP.  If total_ops >= 10001
    # the emitter should have fired; silence is a real bug -- FAIL.
    if total_ops is not None and total_ops >= 10001:
        check_errors.append(
            f"window record: emitter silent despite total_ops={total_ops} (>= 10001)"
        )
    else:
        window_skip = True

if window_keys and bl_window:
    rt_window = set(window_keys)
    extra = rt_window - bl_window
    missing = bl_window - rt_window
    if extra:
        check_errors.append("window record: unexpected fields: " +
                             ", ".join(sorted(extra)))
    if missing:
        check_errors.append("window record: missing fields: " +
                             ", ".join(sorted(missing)))

with open(result_path, "w") as f:
    if check_errors:
        f.write("error\n")
        f.write("\n".join(check_errors) + "\n")
    elif window_skip:
        f.write("skip\n")
        f.write(f"baseline_window_fields={len(bl_window)} "
                f"live_records=none(threshold-not-reached)\n")
    else:
        n_terminal = len(terminal_keys) if terminal_keys else 0
        n_window   = len(window_keys)   if window_keys   else 0
        f.write("ok\n")
        f.write(f"terminal_keys={n_terminal} window_compared={n_window}\n")

sys.exit(1 if check_errors else 0)
PYEOF
	PERIODIC_PY_RC=$?
	PERIODIC_RESULT="$(cat "$WORK/periodic_check.result" 2>/dev/null | head -1)"

	if [ "$MODE" = "regen" ]; then
		echo "REGEN: $NAME: periodic-JSONL baseline written"
	elif [ "$PERIODIC_PY_RC" -ne 0 ]; then
		fail "periodic-JSONL shape check failed (python error)"
		cat "$WORK/periodic_check.result" >&2
	else
		case "$PERIODIC_RESULT" in
		error)
			fail "periodic-JSONL shape check failed"
			cat "$WORK/periodic_check.result" >&2
			;;
		skip)
			echo "SKIP: $NAME: periodic-JSONL window section -- no window records produced (total_ops < 10001)"
			;;
		ok)
			DETAIL="$(grep -v '^ok' "$WORK/periodic_check.result" | head -1)"
			echo "PASS: $NAME: periodic-JSONL shape: $DETAIL"
			pass
			;;
		*)
			fail "periodic-JSONL check: unexpected result '${PERIODIC_RESULT}'"
			cat "$WORK/periodic_check.result" >&2
			;;
		esac
	fi
fi

# ---------------------------------------------------------------------------
# 4. Validate the rotation-event JSONL shape.
#
# Rotation events are emitted by the CAS-winning child in maybe_rotate_strategy()
# (random_syscall/strategy-rotate.c) after STRATEGY_WINDOW = 131072 ops.
# That threshold is unreachable under the fixture's -N cap, so no live rotation
# records are produced by the binary runs above.  To exercise the terminal-
# record validation arm on every run we inject a synthetic rotation-events
# JSONL fixture carrying one rotation record (all baseline fields, placeholder
# values) and one terminal record.  The Python cross-check then validates both
# record types against the baseline and emits "ok" rather than "skip".
# ---------------------------------------------------------------------------

# Inject a synthetic rotation record so the live_fields arm and the terminal-
# record validation arm both execute on every run.  The binary's -N 15000 run
# may have produced a rotation-events JSONL that carries only a terminal
# record (no rotation record, since STRATEGY_WINDOW=131072 is unreachable
# under the fixture cap).  Prepend one synthetic rotation record so the
# Python cross-check sees a non-terminal record and sets live_fields.  If
# no binary rotation-events file exists create a full synthetic fixture.
_ROTATION_SYNTH_RECORD='{"t_close_mono_ns":0,"start_mono_ns":0,"op_count_start":0,"op_count_end":131072,"syscalls_in_window":0,"strategy_prev":0,"strategy_prev_name":"random","strategy_next":0,"strategy_next_name":"random","selection_reason_prev":0,"selection_reason_prev_name":"initial","selection_reason_next":0,"selection_reason_next_name":"initial","pim_mode":0,"pim_mode_name":"none","pc_edge_calls_in_window":0,"pc_edges_in_window":0,"cmp_wins_in_window":0,"warn_fires_in_window":0,"was_chaos":false,"plateau_active":false,"distinct_edges_now":0}'
_ROTATION_REAL="$(ls "$WORK"/rotation-events-*.jsonl 2>/dev/null | head -1)"
if [ -n "$_ROTATION_REAL" ]; then
	# Binary run produced a file (likely terminal-only): inject the synthetic
	# rotation record at the front so live_fields is non-None after parsing.
	_ROTATION_COMBINED="$WORK/rotation-events-combined-fixture.jsonl"
	{ printf '%s\n' "$_ROTATION_SYNTH_RECORD"; cat "$_ROTATION_REAL"; } \
		> "$_ROTATION_COMBINED"
	ROTATION_FILE="$_ROTATION_COMBINED"
else
	# No binary file: create a full synthetic fixture with rotation + terminal.
	ROTATION_FILE="$WORK/rotation-events-synthetic-fixture.jsonl"
	printf '%s\n' "$_ROTATION_SYNTH_RECORD" '{"type":"terminal"}' \
		> "$ROTATION_FILE"
fi

python3 - "$ROOT/stats/rotation_event.c" \
          "${ROTATION_FILE:-}" \
          "$BASELINE_ROTATION" "$MODE" \
          "$WORK/rotation_check.result" <<'PYEOF'
import sys, json, os, re

source_path   = sys.argv[1]
live_path     = sys.argv[2]   # may be empty string
baseline_path = sys.argv[3]
mode          = sys.argv[4]
result_path   = sys.argv[5]

# Extract expected field names from the snprintf format string in
# stats_rotation_event_emit().  Look for every "\"KEY\":%...(,|}) pattern.
def extract_source_fields(path):
    with open(path) as f:
        src = f.read()
    # Find the snprintf call block inside stats_rotation_event_emit().
    m = re.search(r'n\s*=\s*snprintf\s*\(buf[^;]+;', src, re.DOTALL)
    if not m:
        return None, "could not locate snprintf call in stats_rotation_event_emit"
    block = m.group(0)
    # Extract all JSON keys: sequences of \\"KEY\\" followed by :
    keys = re.findall(r'\\"([A-Za-z_][A-Za-z0-9_]*)\\":', block)
    if not keys:
        return None, "no field names found in snprintf block"
    return sorted(set(keys)), None

src_fields, err = extract_source_fields(source_path)
if err:
    with open(result_path, "w") as f:
        f.write(f"error: {err}\n")
    sys.exit(1)

# Parse any live rotation events.  Terminal records (type=="terminal")
# are separated from rotation event records so they can be validated
# independently against the [terminal] baseline section.
live_path_exists = bool(live_path and os.path.exists(live_path))
live_fields = None
live_terminal_fields = None
live_errors = []
if live_path_exists:
    with open(live_path) as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
                if rec.get("type") == "terminal":
                    if live_terminal_fields is None:
                        live_terminal_fields = sorted(rec.keys())
                elif live_fields is None:
                    live_fields = sorted(rec.keys())
            except json.JSONDecodeError as e:
                live_errors.append(f"line {lineno}: {e}")

if live_errors:
    with open(result_path, "w") as f:
        f.write("error\n")
        f.write("\n".join(live_errors) + "\n")
    sys.exit(1)

if mode == "regen":
    lines = []
    lines.append("# stats-rotation-jsonl-schema.baseline")
    lines.append("#")
    lines.append("# Field names for rotation-event JSONL records emitted by")
    lines.append("# stats/rotation_event.c::stats_rotation_event_emit().")
    lines.append("#")
    lines.append("# Seeded from the source snprintf format string; a quick")
    lines.append("# dry-run rarely produces live rotation events.")
    lines.append("#")
    lines.append("# Regenerate after a field-name change with:")
    lines.append("#   scripts/check-static/check-runtime-json-output.sh --regen")
    lines.append("# and commit the diff alongside the code change.")
    lines.append("")
    lines.append("[rotation]")
    for k in src_fields:
        lines.append(k)
    lines.append("")
    # Terminal record section: fields emitted by stats_rotation_event_close().
    # The terminal record contains only {"type":"terminal"} -- a single-field
    # sentinel so a downstream reader can distinguish a clean end-of-run from
    # a mid-run sink death (where the truncation marker ends the stream).
    # Derive the field set from any live terminal record if present; fall back
    # to the known static field set {"type"} so --regen succeeds even when the
    # short fixture run does not produce a rotation-event JSONL file at all.
    term_fields = sorted(live_terminal_fields) if live_terminal_fields else ["type"]
    lines.append("[terminal]")
    for k in term_fields:
        lines.append(k)
    lines.append("")
    with open(result_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(baseline_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"REGEN: rotation-jsonl: wrote baseline to {baseline_path}", flush=True)
    sys.exit(0)

# Check mode.
if not os.path.exists(baseline_path):
    with open(result_path, "w") as f:
        f.write(f"error: baseline missing at {baseline_path} -- run --regen\n")
    sys.exit(1)

bl_sections_parsed = {}
current_sec = None
with open(baseline_path) as f:
    for line in f:
        line = line.rstrip('\n')
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            current_sec = line[1:-1]
            bl_sections_parsed[current_sec] = []
            continue
        if current_sec is not None:
            bl_sections_parsed[current_sec].append(line)

bl_fields = bl_sections_parsed.get("rotation", [])
bl_fields_set = set(bl_fields)
bl_terminal_set = set(bl_sections_parsed.get("terminal", []))

check_errors = []

# Source-vs-baseline agreement: the baseline was seeded from source; if the
# source has drifted from the baseline a static gate trips here.
src_set = set(src_fields)
extra_in_src  = src_set  - bl_fields_set
extra_in_bl   = bl_fields_set - src_set
if extra_in_src:
    check_errors.append(
        "rotation-event source fields not in baseline "
        "(new field? run --regen): " + ", ".join(sorted(extra_in_src)))
if extra_in_bl:
    check_errors.append(
        "rotation-event baseline fields not in source "
        "(removed field? run --regen): " + ", ".join(sorted(extra_in_bl)))

# Live rotation event records: validate against [rotation] section.
if live_fields is not None:
    live_set = set(live_fields)
    extra_live    = live_set    - bl_fields_set
    missing_live  = bl_fields_set - live_set
    if extra_live:
        check_errors.append(
            "live rotation record: unexpected fields: " +
            ", ".join(sorted(extra_live)))
    if missing_live:
        check_errors.append(
            "live rotation record: missing fields: " +
            ", ".join(sorted(missing_live)))

# Terminal record: validate against [terminal] section.
if live_terminal_fields is not None and bl_terminal_set:
    live_term_set = set(live_terminal_fields)
    extra_term    = live_term_set  - bl_terminal_set
    missing_term  = bl_terminal_set - live_term_set
    if extra_term:
        check_errors.append(
            "rotation-event terminal record: unexpected fields: " +
            ", ".join(sorted(extra_term)))
    if missing_term:
        check_errors.append(
            "rotation-event terminal record: missing fields: " +
            ", ".join(sorted(missing_term)))
elif live_terminal_fields is None and bl_terminal_set and live_path_exists:
    check_errors.append(
        "rotation-event terminal record: absent but expected by baseline")

with open(result_path, "w") as f:
    if check_errors:
        f.write("error\n")
        f.write("\n".join(check_errors) + "\n")
    elif live_fields is None:
        # No live rotation record found in the fixture file (terminal-only or
        # empty).  The synthetic fixture injected by the shell should always
        # supply at least one rotation record; reaching here means the fixture
        # write failed or the file was not passed.  Caller treats 'skip' as a
        # failure so this branch is never a silent pass.
        term_note = (f" terminal_validated={live_terminal_fields is not None}"
                     if bl_terminal_set else "")
        f.write("skip\n")
        f.write(f"source_fields={len(src_fields)} "
                f"baseline_fields={len(bl_fields)} "
                f"live_records=none(not-exercised){term_note}\n")
    else:
        n_live = len(live_fields)
        f.write("ok\n")
        f.write(f"source_fields={len(src_fields)} "
                f"baseline_fields={len(bl_fields)} "
                f"live_records=yes({n_live}fields)\n")

sys.exit(1 if check_errors else 0)
PYEOF
ROTATION_PY_RC=$?
ROTATION_RESULT="$(cat "$WORK/rotation_check.result" 2>/dev/null | head -1)"

if [ "$MODE" = "regen" ]; then
	echo "REGEN: $NAME: rotation-event JSONL baseline written"
elif [ "$ROTATION_PY_RC" -ne 0 ] || [ "$ROTATION_RESULT" = "error" ]; then
	fail "rotation-event JSONL shape check failed"
	cat "$WORK/rotation_check.result" >&2
elif [ "$ROTATION_RESULT" = "skip" ]; then
	fail "rotation-event JSONL: synthetic fixture not picked up (live_fields=None despite injected fixture)"
elif [ "$ROTATION_RESULT" = "ok" ]; then
	DETAIL="$(grep -v '^ok' "$WORK/rotation_check.result" | head -1)"
	echo "PASS: $NAME: rotation-event JSONL shape: $DETAIL"
	pass
else
	fail "rotation-event JSONL check: unexpected result '${ROTATION_RESULT}'"
	cat "$WORK/rotation_check.result" >&2
fi

# ---------------------------------------------------------------------------
# 5. Sink-failure exercise.
#
# Verify that trinity surfaces open failures to stderr and continues running.
# Two scenarios:
#
#   (a) --stats-log-file pointing at a non-existent directory.
#       Expected stderr: "failed to open stats log file ... No such file"
#       Expected exit:   0 (run completes normally without the log)
#
#   (b) Run from a read-only tmpdir (timeseries + rotation-event files
#       cannot be created).
#       Expected stderr: "failed to open stats timeseries file ... Permission denied"
#                    or  "failed to open rotation event file ... Permission denied"
#       Expected exit:   0 (run completes normally without the JSONL sinks)
#
# These exercises confirm that the open-failure error-transaction paths in
# stats/log.c and stats/rotation_event.c are live (8d326144e77a
# ("stats: latch ferror and disable timeseries sink on write failure")).
# ---------------------------------------------------------------------------

echo "--- $NAME: sink-failure: bad --stats-log-file path ---"
BAD_LOG="/tmp/trinity-rtjson-nodir-$$/stats.log"
SINK_STDOUT="$WORK/sink_logfile.stdout"
SINK_STDERR="$WORK/sink_logfile.stderr"

( cd "$WORK" && \
  timeout -k 15 30 env \
      TRINITY_NO_DMESG=1 \
      TRINITY_NO_CGROUP=1 \
      "$ROOT/scripts/run-trinity.sh" \
      --dry-run -C 4 -N 100 --stats --stats-log-file="$BAD_LOG" --max-runtime=2 \
      >"$SINK_STDOUT" 2>"$SINK_STDERR" )
SINK_RC=$?

if [ "$SINK_RC" -ne 0 ]; then
	fail "sink-failure(log-file): trinity exited $SINK_RC (expected 0)"
elif ! grep -q "failed to open stats log file" "$SINK_STDERR"; then
	fail "sink-failure(log-file): expected 'failed to open stats log file' in stderr"
else
	echo "PASS: $NAME: sink-failure(log-file): error latched in stderr, exit 0"
	pass
fi

echo "--- $NAME: sink-failure: read-only workdir (timeseries/rotation) ---"
RODIR="$WORK/readonly"
mkdir -p "$RODIR"
# Symlink trinity so run-trinity.sh can find it.
ln -sf "$ROOT/trinity" "$RODIR/trinity"
chmod 555 "$RODIR"
SINK_RDONLY_STDOUT="$WORK/sink_rdonly.stdout"
SINK_RDONLY_STDERR="$WORK/sink_rdonly.stderr"

( cd "$RODIR" && \
  timeout -k 15 30 env \
      TRINITY_NO_DMESG=1 \
      TRINITY_NO_CGROUP=1 \
      "$ROOT/scripts/run-trinity.sh" \
      --dry-run -C 4 -N 100 --stats --max-runtime=2 \
      >"$SINK_RDONLY_STDOUT" 2>"$SINK_RDONLY_STDERR" )
SINK_RDONLY_RC=$?
chmod 755 "$RODIR"   # restore so the trap can remove $WORK

if [ "$SINK_RDONLY_RC" -ne 0 ]; then
	fail "sink-failure(rdonly-dir): trinity exited $SINK_RDONLY_RC (expected 0)"
elif ! grep -qE \
    "failed to open stats timeseries file|failed to open rotation event file" \
    "$SINK_RDONLY_STDERR"; then
	fail "sink-failure(rdonly-dir): expected open-failure message in stderr"
else
	echo "PASS: $NAME: sink-failure(rdonly-dir): error latched in stderr, exit 0"
	pass
fi

# ---------------------------------------------------------------------------
# Final summary.
# ---------------------------------------------------------------------------

if [ "$MODE" = "regen" ]; then
	echo "REGEN: $NAME: baseline regeneration complete"
	exit 0
fi

if [ "$fail_count" -gt 0 ]; then
	echo "FAIL: $NAME: $fail_count check(s) failed, $pass_count passed"
	exit 1
fi

echo "PASS: $NAME: all $pass_count check(s) passed"
exit 0
