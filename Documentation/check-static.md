# check-static

`make check-static` runs a battery of structural consistency checks
against the source tree.  It is the bridge between "the code compiled"
and "the code is internally consistent."  The checks are cheap (target
is single-digit seconds) and require no runtime execution beyond what
`make` already does.

Trinity's fuzzer binary cannot safely run on developer hosts; it only
runs on an isolated fuzz machine.  Architectural invariants that would
normally surface as a runtime assertion failure therefore have to be
caught earlier.  `check-static` is where that catching happens.

## Running

    make check-static

Each check prints one of:

    PASS: <check-name>                       (exit 0, counted)
    WARN: <check-name>: <message>            (exit 0, counted; tripwire)
    FAIL: <check-name>: <details on stderr>  (exit 1, counted)

The orchestrator exits 0 if every check passed (warnings allowed) or 1
if any check failed.  Detailed failure output goes to stderr.

## Skipping a check

    CHECK_STATIC_SKIP=check-alt-op-rotation,post-state-magic make check-static

Comma-separated list of check basenames (without `.sh`).

## Adding a check

Drop an executable shell script into `scripts/check-static/`.  The file
name (minus `.sh`) is the check name and what `CHECK_STATIC_SKIP`
matches against.  The script may rely on `$REPO_ROOT` (exported by the
orchestrator) to locate sources.  Conventions:

- Print exactly one `PASS:` / `WARN:` / `FAIL:` line on stdout.
- Emit detail on stderr.
- Return 0 on pass/warn, non-zero on fail.
- Keep runtime under one second; the whole battery should stay fast
  enough that contributors run it after every edit.

## What today's checks enforce

(See each script for the precise rule.  This list is hand-maintained;
when scripts are added to or removed from `scripts/check-static/`,
update this section to match `ls scripts/check-static/*.sh`.)

- `check-stats-reachable`: every field in `struct stats_s` must have a
  `STAT_FIELD*()` descriptor row, a consumer read, or an allowlist entry
  naming its bespoke walker.  Catches a counter that is written and then
  never surfaced.

- `stats-group-has-producer`: the complement -- every group in
  `struct stats_s` must be written by something outside `stats/`.  A group
  with a descriptor and no writer renders as an all-zero object forever, and
  a consumer cannot tell "ran, found nothing" from "was deleted".  Counts
  writers in the direct, `offsetof()` and `parent_stats` forms; self-tests
  the `offsetof()` form, which a naive grep misses.

- `check-static-doc-parity`: every `scripts/check-static/*.sh` must have a
  row in the list below, and every row must name a script that exists.  The
  battery is the project's change detector; a check nobody can find in the
  docs is a check nobody knows they lost.

- `check-runtime-json-output`: spawn the binary under the sanctioned
  capped form (`timeout`/`TRINITY_NO_DMESG`/`--dry-run`), then
  cross-check all three machine-readable output surfaces against
  their baselines: (1) final stats JSON (`--stats-json`) key-paths
  and value-types versus the source-reconstruction baseline produced
  by `stats-json-schema.sh` — a source-reconstruction error and a
  binary-emission error produce different failures; (2) periodic
  JSONL terminal-record field names versus
  `stats-periodic-jsonl-schema.baseline` (the -N 15000 run crosses
  the >10000-op window-emit threshold so both terminal and window
  records are validated); (3) rotation-event JSONL field names against
  the source-derived `stats-rotation-jsonl-schema.baseline`
  (source-vs-baseline agreement only — live rotation events require
  STRATEGY_WINDOW = 131072 ops, which is unreachable under the fixture
  cap; a run that produces no records emits SKIP, never a silent PASS).
  Also exercises sink-failure end-to-end: open failures for
  `--stats-log-file` and the auto-named timeseries/rotation files are
  verified to surface in stderr with exit 0.
- `json-separator-adjacency`: detect missing `putchar(',')` separators
  between adjacent `stat_category_emit_json()` calls within a function
  in `stats/json/*.c`.  A missing comma produces a malformed-JSON
  document that silently passes the static schema gate (which
  reconstructs from source without parsing binary output) and every
  runtime gate that does not exercise the affected path.  The detector
  tracks the last `stat_category_emit_json()` call per function, resets
  on any comma-separator emit (`putchar(',')` / `fputc(',` /
  `printf(",`), and flags a second emit reached with no separator
  between.  Regression fixture: the pre-fix pre-image of
  `dump_stats_json_netfilter_and_xfrm()` (872757fb803b ("stats/json: fix missing comma before ip6mr_churn in network section")^) is replayed
  inline as a known-bad input and must produce exactly one hit.
- `no-bare-waitpid`: reject bare `waitpid()` callsites outside the
  `waitpid_eintr()` wrapper (`include/utils.h`) and the wait-family
  syscall definitions (`syscalls/process/wait4.c`, `waitpid.c`,
  `waitid.c`).  Trinity installs `SIGALRM` / `SIGXCPU` without
  `SA_RESTART`, so a non-wrapper blocking `waitpid()` can return
  `-1/EINTR`; treating that as "done" leaves a child unreaped and
  can strand a worker on a torn-down shared mapping.
- `no-libc-rand`: reject libc PRNG callsites (`rand`, `random`,
  `srand`, `*rand48`) outside the `rand/` wrapper layer and
  `include/rnd.h`.
- `no-unchecked-alloc-shared-str`: every `alloc_shared_str()` /
  `alloc_shared_strdup()` assignment must have a NULL guard on the
  lvalue within 4 lines.  Both functions are `__must_check`
  (`include/utils-mem.h`), which catches a fully discarded return but
  not the assign-then-use-without-check pattern.  Trinity's shared-str
  heap has a 1 MiB ceiling so NULL is a genuinely reachable return; a
  caller that publishes a NULL pointer into an object's `filename` /
  `name` field would produce a `strlen` / `free` NULL-deref in the
  dump or destructor path, far from the allocation site.
- `no-time-subtraction`: reject duration arithmetic of the form
  `time(NULL) - start` or `end - time(NULL)` in `*.c`/`*.h`.
  A wall-clock duration goes negative (or wraps to an enormous
  unsigned value) when NTP steps the clock backwards; all runtime
  timing must use `mono_ns()` / `CLOCK_MONOTONIC`.  Comment lines
  are stripped so the existing hazard note in
  `syscalls/timer/timer_settime.c` does not false-positive.
- `objpool-array-gen`: enforce the `array_generation` invariant on
  `struct objhead` in `include/objects.h` and `objects/registry*.c`
  -- (i) the field exists, (ii) `get_random_object()` routes its
  indexed load through `objhead_indexed_read()` (no bare
  `head->array[idx]`), and (iii) every site that frees or replaces
  `head->array` is followed within a small window by
  `head->array_generation++`.  Guards the deferred-free / TTL grow /
  teardown class where a captured `head->array` pointer becomes a
  chunk glibc has already recycled.
- `post-state-deref`: every `.post` handler that dereferences a
  pointer read from `rec->post_state` must first gate it with
  `looks_like_corrupted_ptr()` or a `*_POST_STATE_MAGIC` cookie
  compare.
- `post-state-magic`: every `struct *_post_state` in `syscalls/` must
  begin with `unsigned long magic` and ship a matching
  `*_POST_STATE_MAGIC` constant -- the convention that prevented the
  ppoll bad-free regression class.  Grandfathered structs that predate
  the convention are listed in
  `scripts/check-static/post-state-magic.baseline`; that list should
  shrink over time, never grow.
- `post-state-ownership`: every `.sanitise` handler that stamps a
  `*_POST_STATE_MAGIC` cookie into a freshly-allocated post_state
  struct must also call `post_state_install()` or
  `post_state_register()` to wire the chunk into the ownership
  table.  Closes the third leg beneath `post-state-magic` and
  `post-state-deref`: without ownership registration a sibling stomp
  can redirect `rec->post_state` at a foreign chunk with a matching
  cookie value and the `.post` handler clears the wrong struct.
  Grandfathered handlers live in `post-state-ownership.baseline`.
- `shared-region-budget`: tripwire that warns when the number of
  shared-region producer call sites approaches `MAX_SHARED_ALLOCS`.
  Silent under-protection is the bug class, not loud over-protection.
- `shm-latch-direct`: latch fields of `struct shm_s` (`exit_reason`,
  `current_strategy`, `current_selection_reason`,
  `plateau_current_hypothesis`) must only be read or written through
  `__atomic_*` intrinsics; a plain `shm->field` access is a torn write
  that breaks the publish ordering.
- `signal-handler-async-unsafe`: forbid async-signal-UNSAFE libc calls
  (`snprintf`, `malloc`, `fopen`, `syslog`, ...) inside known signal
  handlers discovered in `signals.c`.
- `srec-no-lock-around-publish`: flag any `lock(&...->lock)`
  immediately preceding a `srec_publish_begin(...)` or any
  `unlock(&...->lock)` immediately following a `srec_publish_end(...)`
  (with at most a blank line / single comment in between).  The srec
  publish brackets are a self-sufficient writer-side ordering anchor;
  re-adding the `rec->lock` pair around them reintroduces the very
  lock the strengthening commit set out to remove.
- `stats-json-schema`: pin the structural shape of the `--stats-json`
  document -- key-path + value-type in emission order, with
  descriptor-driven `STAT_FIELD*()` keys folded in and nested
  key paths (e.g. `stats.fault_injection.armed_fail_nth`) preserved
  -- against a golden baseline.  Catches renamed keys, retyped
  values, reordered emission, and duplicate keys at the same scope
  that would otherwise silently break downstream scrapers.
  Regenerate with `--regen` and review the baseline diff.
- `stats-ring-op-clock-atomic`: every access to `lossless_op_count`
  in production `.c` files (excluding `tests/`) must be lexically
  inside an `__atomic_` call on the same source line.  The parent
  reads the field with `__atomic_load_n`; a plain store or increment
  races with that load and is C11 undefined behaviour regardless of
  whether x86-64 or arm64 codegen happens to be correct today.  Both
  writers must use `__atomic_fetch_add(..., __ATOMIC_RELAXED)`;
  `RELAXED` is correct because the child is the sole writer and
  nothing orders against this counter on either side.
- `strip-c-comments-selftest`: selftest for the `strip_c_comments()`
  helper in `lib.sh`.  Asserts that `/*` and `//` inside a C string
  literal or char literal do not open comment state: a `getppid() == 1`
  on the line after a `"a /* b"` string survives stripping, a `//`
  inside `"http://..."` does not erase the rest of the line, and
  a real block comment is still stripped.  Without these invariants
  every gate that sources `lib.sh` and greps the stripped output is
  silently fail-open on lines that follow a string-embedded `/*`.
- `test-bin-asan-suite`: builds `tests/test-bin-asan` (the
  PURE-module test binary under `-fsanitize=address`) and runs the
  `stats_opclock_lossless_self_check` suite, which gates the per-child
  lossless op-count plausibility guards: absolute ceiling, per-drain
  delta ceiling, and first-drain scribble rejection.  Catches a red
  fixture suite before it escapes to the tree.
- `syscall-metadata`: best-effort sanity on `struct syscallentry` --
  ARG_RANGE arguments must declare low/high bounds.
- `track-shared-region-pairing`: every `track_shared_region()` must
  have a matching `untrack_shared_region()` on every cleanup-goto exit
  path that can free or recycle the backing mapping.
- `uapi-shim-values`: every `#define` shim for an enum-backed UAPI constant
  (families: `IFLA_GRE_*`, `IFLA_IPTUN_*`, `NDA_*`) must carry the correct
  decimal value as recorded in `scripts/check-static/uapi-shim-values.baseline`.
  `#ifndef` guards on enum values are always taken — enums are not macros, so
  the shim is the definition, not a fallback.  A miscounted or typo'd value
  compiles silently and sends the wrong netlink attribute to the kernel.
  `XFRMA_*` value correctness is checked in `netlink-xfrm-attr-shim`.
- `variant-address-walk`: verify both the static reachability walker
  (`struct_desc_has_address_field_depth()` in
  `struct_catalog/address.c`) and the runtime nested-address scrub
  (`scrub_struct_addresses()` in `args/scrub.c`) traverse
  `desc->variants[] / variant->base / variant->nested_variants[]`,
  not just `desc->fields[]`.  Also asserts the
  `selftest_variant_address_walk` runtime BUG() gate is wired into
  the self-check entry point.  Without variant traversal, an
  `FT_ADDRESS` field inside a tagged-union arm (e.g.
  `perf_event_attr.bp_addr` on the BREAKPOINT arm) is invisible to
  the scrub and can alias a shared sibling buffer -- the exact
  heap-corruption class the scrub exists to close.

## Tools

These scripts live under `scripts/` (not `scripts/check-static/`) and are
informational aids, not build gates.  They exit 0 always and produce no
PASS/FAIL lines.

- `scripts/hash-subject-resolver.sh`: given one or more files, extract every
  12–40 char lowercase hex token and attempt to resolve each to a reachable
  commit twin.  Reports FOUND, DANGLING (with/without twin), and
  NOT-AN-OBJECT (with/without twin) categories plus a summary count.  Useful
  after a rebase or cherry-pick wave to locate stale citations before filing
  them as queue fixes.  Run it read-only over any document; it never writes
  to its inputs.

## Hash citation convention

Every hash cited in a commit message, queue row, or review document **must**
be accompanied by its commit subject in the form:

    abc123def456 ("subsystem: brief subject line")

The subject line survives a cherry-pick rewrite; the bare hash does not.
When the cherry-pick wave rewrites ancestors, a reader holding only the hash
has no way to know what the citation meant; a reader holding the subject can
search for the live twin with `git log --oneline --grep "<subject>"` or
`scripts/hash-subject-resolver.sh`.

External hashes (Linux kernel commits, upstream projects) should be prefixed
with `upstream:` so it is clear they are not expected to resolve locally:

    upstream:abc123def456 ("mm: fix some page fault bug")
- `struct-field-offset-size-wrap`: reject bare `->offset +` arithmetic
  in comparison predicates in `args/` when neither operand carries an
  `(unsigned long)` / `(uint64_t)` cast.  Both `struct struct_field`
  members `offset` and `size` are `unsigned int`; the expression
  `f->offset + f->size` wraps modulo 2^32 before comparison when the
  sum exceeds `UINT_MAX`, silently bypassing the bounds guard.  The
  correct form is `f->offset > size || f->size > size - f->offset`.
  Array-index expressions of the form `buf[f->offset + byte_off]` are
  excluded (the index is bounded by an earlier guard).
