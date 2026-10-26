# check-static

`make check-static` runs a battery of structural consistency checks
against the source tree.  It is the bridge between "the code compiled"
and "the code is internally consistent."  The checks are cheap (the whole
battery takes well under a minute) and none of them executes the fuzzer;
the slowest compile probe code or run the unit-test binary.

Trinity's fuzzer binary cannot safely run on developer hosts; it only
runs on an isolated fuzz machine.  Architectural invariants that would
normally surface as a runtime assertion failure therefore have to be
caught earlier.  `check-static` is where that catching happens, and no
check in it executes the binary (`no-trinity-exec` enforces that); the
one fixture that does is the opt-in `make check-runtime` (see below).

## Running

    make check-static

Each check prints one of:

    PASS: <check-name>                       (exit 0, counted)
    WARN: <check-name>: <message>            (exit 0, counted; tripwire)
    FAIL: <check-name>: <details on stderr>  (exit 1, counted)

The orchestrator exits 0 if every check passed (warnings allowed) or 1
if any check failed.  Detailed failure output goes to stderr.

## Skipping a check

    CHECK_STATIC_SKIP=no-time-subtraction,post-state-magic make check-static

Comma-separated list of check basenames (without `.sh`).  A skipped check
prints `SKIP: <check-name> (via CHECK_STATIC_SKIP)` and is not counted.

## Adding a check

Drop an executable shell script into `scripts/check-static/`.  The file
name (minus `.sh`) is the check name and what `CHECK_STATIC_SKIP`
matches against.  The script may rely on `$REPO_ROOT` (exported by the
orchestrator) to locate sources.  Conventions:

- Print exactly one `PASS:` / `WARN:` / `FAIL:` line on stdout.
- Emit detail on stderr.
- Return 0 on pass/warn, non-zero on fail.
- Keep runtime short; the whole battery takes well under a minute and
  should stay fast enough that contributors run it after every edit.
- Never execute the trinity binary or a wrapper that does
  (`scripts/run-trinity.sh`); `no-trinity-exec` fails the battery if a
  check names one.  A fixture that has to run it belongs behind
  `make check-runtime`, not in this directory.

## Runtime check (opt-in)

    make check-runtime

`scripts/check-runtime-json-output.sh` is the one fixture that executes
the binary, so `check-static` never runs it.  `make check-runtime`
builds `./trinity` first; run it only on a host where starting the
fuzzer is acceptable.  The fixture spawns the binary under the
sanctioned capped form (`timeout`/`TRINITY_NO_DMESG`/`--dry-run`), then
cross-checks all three machine-readable output surfaces against their
baselines: (1) final stats JSON (`--stats-json`) key-paths and
value-types versus the source-reconstruction baseline produced by
`stats-json-schema.sh` — a source-reconstruction error and a
binary-emission error produce different failures; (2) periodic JSONL
terminal-record field names versus
`scripts/check-static/stats-periodic-jsonl-schema.baseline` (the
`-N 15000` run crosses the >10000-op window-emit threshold so both
terminal and window records are validated); (3) the live rotation-event
JSONL terminal record against the `[terminal]` section of
`scripts/check-static/stats-rotation-jsonl-schema.baseline`, and any
live rotation record against its `[rotation]` section (live rotation
events require STRATEGY_WINDOW = 131072 ops, which is unreachable under
the fixture cap, so a synthetic record built from the baseline keeps
that arm exercised, and a missing one fails rather than skips; the
source side of both sections is pinned by the static
`stats-rotation-jsonl-schema` check).  Also exercises sink-failure
end-to-end: open failures for `--stats-log-file` and the auto-named
timeseries/rotation files are verified to surface in stderr with exit 0.

## Older-uapi build (opt-in)

    make uapi-check [KERNEL_SRC=<kernel git tree>] [UAPI_TAG=<tag>]

Compiles every trinity and test-binary object against the uapi headers
of an older kernel tag (v6.12 by default), so a symbol used without a
`#ifndef` or `HAVE_` fallback fails here rather than on a distribution
with older headers.  It needs a local kernel git tree, which
`check-static` cannot assume, so it stays out of the battery.
`Documentation/HACKING.txt` covers the floor and the failure summary.

## What today's checks enforce

(See each script for the precise rule.  This list is hand-maintained;
when scripts are added to or removed from `scripts/check-static/`,
update this section to match `ls scripts/check-static/*.sh`.)

- `check-reexec-coverage`: every `struct syscallentry` in `syscalls/` with
  a `.sanitise` must say what the CMP RedQueen re-exec step does with it:
  `REEXEC_SANITISE_OK` or `AVOID_REEXEC` in its flags, a one-line
  `Not REEXEC_SANITISE_OK: <reason>` comment inside the entry, or a line
  in `scripts/check-static/check-reexec-coverage.baseline` for a
  sanitiser that opts in per call with `rec->flags |= REEXEC_OK`.  A new
  sanitiser otherwise drops out of re-exec by default, counted in
  `reexec_skipped_destructive` with nothing to say anyone decided it.
  The flags have to be code: naming one in a comment does not count.
  The baseline only shrinks: a line fails once its entry gains an
  annotation of its own or its file stops setting `REEXEC_OK`.  The scan
  is textual and fails closed -- an entry whose end it cannot find, a
  `.sanitise` outside any entry, or too few entries is an error, not a
  pass.  Self-tests both directions on planted trees, including a flag
  named only in a comment, a rejection note with no reason, and baseline
  lines for an entry that is annotated or whose file never sets
  `REEXEC_OK`.

- `reexec-pointer-write`: a `REEXEC_SANITISE_OK` entry whose sanitiser
  (found by name in the entry's own file) stores a pointer into `rec->aN`
  -- an allocator result (`get_writable_*`, `get_address`, `zmalloc`...)
  or an address-of -- must be listed in
  `scripts/check-static/reexec-pointer-write.baseline`.  The baseline
  only shrinks.  The scan is textual and line-based, with a self-test on
  a planted tree.

- `check-stats-reachable`: every scalar in the `struct stats_s` tree -- the
  flat members and every leaf of the nested `stats/subsys/*.h` structs --
  must have a `STAT_FIELD*()` descriptor row, a consumer read (a producer
  write does not count) or an allowlist entry naming its bespoke walker.
  Catches a counter that is written and then never surfaced.

- `stats-group-has-producer`: the complement -- every group in
  `struct stats_s` must be written by something outside `stats/`.  A group
  with a descriptor and no writer renders as an all-zero object forever, and
  a consumer cannot tell "ran, found nothing" from "was deleted".  Counts
  writers in the direct, `offsetof()` and `parent_stats` forms; self-tests
  the `offsetof()` form, which a naive grep misses.

- `shim-symbol-single-value`: a uapi fallback symbol -- one guarded by
  `#ifndef SYM` anywhere in the tree, or by `#ifndef HAVE_SYM`, the guard of
  an enum member that `configure` compile-tests -- must have exactly one
  value.  Two values for one symbol means two translation units disagree
  about the ABI while the build stays green, which is how `struct ns_id_req`
  ran as a 24-byte layout in `struct_catalog/` and a 32-byte one in
  `include/kernel/nsfs.h`.  Per-arch and file-local constants are out of
  scope: they are unguarded and are allowed to differ.  Self-tests both
  directions -- a planted guarded conflict, `HAVE_SYM` guard included, must
  fire; a planted unguarded one, or one under another symbol's `HAVE_`
  guard, must not.

- `shim-cross-tu`: a uapi fallback written into a `.c` file -- a
  `#define` in the true branch of an `#ifndef` or `#if !defined()` block,
  whether the guard names the symbol itself, another member of its
  family or a configure `HAVE_` probe -- must stay local to that file.
  It fails when another `.c` carries its own copy, or when any other `.c`
  or any `.h` uses the symbol: against a kernel-headers package that
  predates it, the file holding the copy builds while the one relying on
  the system header does not, and the copies drift apart unseen.  The fix
  is the `include/kernel/<header.h>` mirror of the kernel header the
  symbol comes from.  A use is an identifier token outside comments and
  literals; names tested by `#ifdef`, `#ifndef` or `defined()`, dropped
  by `#undef` or defined in an `#else` branch do not count, nor does a
  header's own guarded copy, and `scripts/` is not read.  Self-tests both
  directions on a planted tree, and fails if the scan finds fewer than
  200 fallbacks.

- `check-static-doc-parity`: every `scripts/check-static/*.sh` must have a
  row in the list below, and every row must name a script that exists.  The
  battery is the project's change detector; a check nobody can find in the
  docs is a check nobody knows they lost.

- `json-separator-adjacency`: detect missing `putchar(',')` separators
  between adjacent `stat_category_emit_json()` calls within a function
  in `stats/json/*.c`.  A missing comma produces a malformed-JSON
  document that silently passes the static schema gate (which
  reconstructs from source without parsing binary output) and every
  runtime gate that does not exercise the affected path.  The detector
  tracks the last `stat_category_emit_json()` call per function, resets
  on any comma-separator emit (`putchar(',')` / `fputc(',` /
  `printf(",`), and flags a second emit reached with no separator
  between.  It also flags the mirror defect -- a separator whose emit is
  gone, leaving two separators back to back and a `,,` in the document.
  That is the residue a deleted stats category leaves, so it arrives
  whenever a childop and its stats category are deleted together.  Both directions
  carry a fixture and a negative control.  Regression fixture: the pre-fix pre-image of
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
  `srand`, `*rand48`) anywhere but `rand/rand-warn.c`, the runtime
  tripwire whose warning text spells `rand()`.
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
- `no-trinity-exec`: nothing in the static battery may start trinity.
  Neither `scripts/check-static.sh` nor any script in
  `scripts/check-static/` may name the binary (any path whose last
  component is `trinity`, as the launcher scripts spell it:
  `$TRINITY_PATH/trinity`, `./trinity`, `$(pwd)/trinity`), a launcher
  or process tool (`run-trinity.sh`, `killtrin.sh`, `trinity-gdb-*.sh`,
  `test-multi.sh`, `test-vm.sh`, `rand-vm.sh`, `test-all-syscalls-*.sh`,
  `find.sh`) or the opt-in runtime fixture and its make target
  (`check-runtime*`), because the battery has to stay runnable on hosts
  where the fuzzer must not run.  Whole-line comments are skipped, so a
  gate can cite the fixture, and a path has to end in `trinity` to
  match, so cache and tmp paths that merely contain the word do not.  A
  binary found on `PATH`, or a path assembled elsewhere, is not caught:
  this is a tripwire, not a sandbox.  The gate is exempt from its own
  scan, since it has to spell the patterns.  Self-tests both directions:
  planted binary, launcher and fixture references must fire; a planted
  comment, a `lib-find.sh` helper and the cache, tmp and awk-comment
  lines that contain the word must not.
- `objpool-array-gen`: enforce the `array_generation` invariant on
  `struct objhead` in `include/objects.h` and `objects/registry*.c`
  -- (i) the field exists, (ii) `get_random_object()` routes its
  indexed load through `objhead_indexed_read()` (no bare
  `head->array[idx]`), and (iii) every site that frees or replaces
  `head->array` is followed within a small window by
  `head->array_generation++`.  Guards the deferred-free / TTL grow /
  teardown class where a captured `head->array` pointer becomes a
  chunk glibc has already recycled.
- `params-value-lists`: the values the tree advertises for a mode option
  must be the values its parser accepts.  The parser is the
  `strcmp(arg, "value")` arms under `strcmp("option", name)` in
  `main/params/*.c`.  They are diffed, in both directions, against the
  option's `--help` row in `help.c` (an `a/b/c`, `a / b` or `a or b`
  list, which every such option must have), the `value` bullets under
  its `## --option` heading in the `.md` files (a heading with none is
  an error) and every inline `--option=a|b|c` in the tracked `.c`,
  `.h`, `.md`, `.txt`, `.1` and `README` files; an untracked scratch
  note is not read, and a tree without `.git` is walked instead.  The
  extractor fails closed: a help row that lists `off` for an option
  with no arms fails, since that parser is one it cannot read, and so
  does a missing `option_descs[]` table, an unreadable row or file, and
  a tree with no arms or no doc sections at all.  It does not read prose
  preambles, bullets written `* x` or `- **x**`, single-value
  `--option=x` examples, help strings that mix `/` and `|`, or the
  parser's own error strings.  Self-tests both directions on synthetic
  parser, help and doc text, including the `!= 0` guard form, an
  unbalanced brace in a string and in a char literal, a slash pair that
  is not a value list, and a tracked-versus-untracked file listing.
- `pidns-init-wiring`: in `child/child-init-sandbox.c`,
  `start_pidns_init()` has to come after `drop_privs()` and the
  `capset()` drop.  The kernel checks the parent-death signal like a
  `kill()` from the dying child, so an idle pid namespace init forked
  any earlier would stay root and miss it from a child running as
  nobody.  `child/child.c` also has to poll `pidns_init_lost()`, or a
  child fuzzes on in a dead namespace.  Comments are stripped first.
- `post-state-deref`: every `.post` handler that dereferences a
  pointer read from `rec->post_state` must first gate it with
  `looks_like_corrupted_ptr()` or a `*_POST_STATE_MAGIC` cookie
  compare.  A handler that uses both the ownership gate
  (`post_state_is_owned()`) and the cookie compare must test ownership
  first: reading `snap->magic` before that trusts memory that a sibling
  stomp may have redirected at a foreign chunk with a matching cookie.
- `post-state-magic`: every `struct *_post_state` in `syscalls/` and
  `lib/` must begin with `unsigned long magic` and ship a matching
  `*_POST_STATE_MAGIC` constant -- the convention that prevented the
  ppoll bad-free regression class.  Grandfathered structs that predate
  the convention are listed in
  `scripts/check-static/post-state-magic.baseline`; it is empty today and
  should stay that way.
- `post-state-ownership`: every `.sanitise` handler that stamps a
  `*_POST_STATE_MAGIC` cookie into a freshly-allocated post_state
  struct must also call `post_state_install()` or
  `post_state_register()` to wire the chunk into the ownership
  table.  `lib/` holds the helpers sanitisers call rather than `.sanitise`
  handlers (`sanitiser_own_fd()` is the setup site for every sanitiser that
  opens an fd it must close), so there every function that assigns a
  `*_POST_STATE_MAGIC` cookie is held to the same rule.  Closes the
  third leg beneath `post-state-magic` and `post-state-deref`: without
  ownership registration a sibling stomp can redirect `rec->post_state`
  at a foreign chunk with a matching cookie value and the `.post`
  handler clears the wrong struct.
  Grandfathered handlers live in `post-state-ownership.baseline`, which is
  empty today.
- `procfs-writer-allow-deny-overlap`: pin the places where an allow rule in
  `childops/fs/procfs-writer.c` overlaps a deny rule.  `add_entry()` admits a
  path when `allow_rules[]` matches or `deny_rules[]` does not, so an overlap
  is a deny that is silently ignored.  Allow-wins is intentional, so the
  pairs are pinned in `procfs-writer-allow-deny-overlap.baseline` rather than
  banned: a new overlap and a pinned pair that no longer overlaps both fail.
  An anchored (`PREFIX`/`EXACT`) pair is found by pattern, unless
  `prefilter_rules[]` already blocks the deny ahead of the allow check; a
  `SUFFIX` deny is found by running `<allow prefix>x<suffix>` through the
  matchers.  The tables are read out of the source: a table, match kind or
  entry the extractor cannot read is an error, not a pass.  The script
  re-implements the C matcher, so a digest of the C functions it mirrors
  (`rule_matches()`, `path_under_discovery_root()`, `path_matches_table()`
  and the three `path_*()` table wrappers) is pinned in it: a change to one
  fails with "matcher changed, re-verify the model" until the model and the
  digest are updated.  Self-tests both directions on synthetic tables, with
  a near-miss per match kind that a looser matcher would accept.  Regenerate
  with `--regen` and review the baseline diff.
- `shared-region-budget`: tripwire that warns when the number of
  shared-region producer call sites approaches `MAX_SHARED_ALLOCS`.
  Silent under-protection is the bug class, not loud over-protection.
- `shm-latch-direct`: latch fields of `struct shm_s` (`exit_reason`,
  `current_strategy`, `current_selection_reason`,
  `plateau_current_hypothesis`, `ready`, `spawn_no_more`,
  `postmortem_in_progress`, and the feature-discovery latches
  `dont_make_it_fail`, `no_fail_nth`, `no_pidns`, `no_private_ns`) must
  only be read or written through `__atomic_*` intrinsics; a plain
  `shm->field` access is a torn write that breaks the publish ordering.
- `signal-handler-async-unsafe`: forbid async-signal-UNSAFE libc calls
  (`snprintf`, `malloc`, `fopen`, `syslog`, ...) inside known signal
  handlers, discovered from the `sa_handler`/`sa_sigaction` assignments in
  `health/signals-policy.c` and checked in `health/signals-policy.c`,
  `signals-fault-handler.c`, `signals-async-safe.c` and `signals-precrash.c`.
- `srec-no-lock-around-publish`: flag any `lock(&...->lock)`
  immediately preceding a `srec_publish_begin(...)` or any
  `unlock(&...->lock)` immediately following a `srec_publish_end(...)`
  (with at most a blank line / single comment in between).  The srec
  publish brackets are a self-sufficient writer-side ordering anchor;
  re-adding the `rec->lock` pair around them reintroduces the very
  lock the strengthening commit set out to remove.
- `stats-json-schema`: pin the structural shape of the `--stats-json`
  document -- key-path + value-type in emission order, with
  descriptor-driven `STAT_FIELD*()` keys and raw descriptor rows
  (array-valued ones included) folded in and nested
  key paths (e.g. `stats.fault_injection.armed_fail_nth`) preserved
  -- against a golden baseline.  Catches renamed keys, retyped
  values, reordered emission, and duplicate keys at the same scope
  that would otherwise silently break downstream scrapers.
  Regenerate with `--regen` and review the baseline diff.
- `stats-rotation-jsonl-schema`: pin the field names of the rotation-event
  JSONL records.  `stats/rotation_event.c` writes the rotation record from
  one `snprintf()` format string in `stats_rotation_event_emit()` and the
  end-of-run record as a plain literal in `stats_rotation_event_close()`;
  the `"key":` names read out of each must equal the `[rotation]` and
  `[terminal]` sections of `stats-rotation-jsonl-schema.baseline`, in both
  directions, so a field added or dropped without regenerating the
  baseline trips the check.  An extractor that stops finding either
  record or its keys is an error, not a pass.  Regenerate with `--regen`
  (both sections come from the source) and review the baseline diff.
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
- `struct-field-offset-size-wrap`: reject bare `->offset +` arithmetic
  in comparison predicates in `args/` and `cmp_hints/` when neither
  operand carries an `(unsigned long)` / `(uint64_t)` cast.  Both
  `struct struct_field` members `offset` and `size` are `unsigned int`;
  the expression `f->offset + f->size` wraps modulo 2^32 before
  comparison when the sum exceeds `UINT_MAX`, silently bypassing the
  bounds guard.  The correct form is
  `f->offset > size || f->size > size - f->offset`.
  Array-index expressions of the form `buf[f->offset + byte_off]` are
  excluded (the index is bounded by an earlier guard).
- `test-bin-asan-suite`: runs `make test-asan`, which builds
  `tests/test-bin-asan` (the PURE-module test binary under
  `-fsanitize=address`) and runs every fixture in it.  They include the
  per-child lossless op-count plausibility guard: per-drain delta ceiling,
  first-drain scribble rejection, and recovery by rebase, including that
  a clock-like scribble never rebases.  Catches a red fixture before it
  escapes to the tree.
- `syscall-metadata`: best-effort sanity on `struct syscallentry` --
  ARG_RANGE arguments must declare low/high bounds.
- `track-shared-region-pairing`: every `track_shared_region()` must
  have a matching `untrack_shared_region()` on every cleanup-goto exit
  path that can free or recycle the backing mapping.
- `uapi-enum-probes`: every enum fallback in `include/kernel/` -- a `#define`
  under `#ifndef HAVE_<SYMBOL>` -- is paired with a `check_enum_member`
  compile-test in `configure` that emits that name, and every symbol
  `configure` probes has such a fallback.  An enum member is not a macro, so
  `#ifndef` cannot tell whether the installed header has it and `configure`
  decides instead.  The two halves are typed by hand in two files, and a name
  that does not match fails silently: a guard nothing emits is always taken,
  so the fallback macro shadows the real member on every host, and a probe
  nothing falls back on probes for nothing.  Also fails a guard whose
  `#define` names another symbol.  Self-tests a planted tree with each
  mismatch, and with a comment that names a guard and the helper's own
  definition, which must not fire.
- `uapi-shim-values`: every integer `#define` in the tree (decimal, hex or a
  single-bit shift) that a probe can resolve, against the installed uapi
  headers or a kernel tree named by `TRINITY_LINUS_SRC`, must carry the
  compiler's value, and so must each pair pinned in
  `scripts/check-static/uapi-shim-values.baseline`.
  `#ifndef` guards on enum values are always taken — enums are not macros, so
  the shim is the definition, not a fallback.  A miscounted or typo'd value
  compiles silently and sends the wrong netlink attribute to the kernel.
  The `XFRMA_*` shims are probed like any other and pinned in the baseline.
  A baseline symbol that the tree shims but no probe can resolve, such as a
  constant newer than the build host's headers, is skipped with a `SKIP` line
  and a count in the `PASS` line instead of failing; a `TRINITY_LINUS_SRC`
  tree that resolves it gets the value checked as usual.  A baseline symbol
  with no integer `#define` in the tree is stale and fails.
  The probe header sets are finite, so a symbol whose header is in none of
  them is out of reach of the compiler.  With a `TRINITY_LINUS_SRC` tree such
  a macro is read as a `#define` out of the headers the tree installs, and
  must carry that value (`text-verified` in the `PASS` line, ratcheted by
  `scripts/check-static/uapi-shim-text-floor.baseline`).  Only an
  unambiguous reading counts: every definition an integer literal or a
  single-bit shift, and all agreeing.  A symbol defined as another macro or an
  expression, or twice with different values, stays unresolved, as do enum
  members, which only a compile probe sees.  Symbols still unresolved are
  reported as one count: `unresolved-uapi` for the uapi-shaped
  ones (ALL_CAPS with an underscore) and `not-uapi-shaped` for names with a
  trinity-owned prefix or no underscore, a few of which are real constants.
  `UAPI_SHIM_VALUES_LIST=1` names the uapi-shaped ones.
- `uapi-shim-values-selftest`: runs `uapi-shim-values` on a scratch tree and
  asserts that a baseline symbol the host's headers lack is skipped, that one
  with no shim in the tree or a wrong pinned value fails, that a kernel tree
  named by `TRINITY_LINUS_SRC` resolves the otherwise-skipped symbol even when
  a hook has exported `GIT_DIR`, that unresolved symbols are one count rather
  than a line each, and, for the text lookup, that a macro only an installed
  header declares is verified, that a wrong value fails in each shape
  (literal, shift, negative, wrapping hex) and names the header, that a symbol
  with disagreeing or non-literal definitions is not judged, and that a floor
  above the verified count fails.  It runs no git (a stub answers the gate's
  revision lookup).  Without it the gate's verdict can drift back to depending
  on how old the build host's kernel headers are, its findings back under a
  line per unresolved symbol, and the text lookup into accusing correct shims
  or passing wrong ones.
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
informational aids, not build gates.  `hash-subject-resolver.sh` exits 0
always and produces no PASS/FAIL lines; `commit-msg-hash-resolves.sh` prints
one and exits 1 on a failure, but nothing in the battery runs it.

- `scripts/hash-subject-resolver.sh`: given one or more files, extract every
  12–40 char lowercase hex token and attempt to resolve each to a reachable
  commit twin.  Reports FOUND, DANGLING (with/without twin), and
  NOT-AN-OBJECT (with/without twin) categories plus a summary count.  Useful
  after a rebase or cherry-pick wave to locate stale citations before filing
  them as queue fixes.  Run it read-only over any document; it never writes
  to its inputs.
- `scripts/commit-msg-hash-resolves.sh [<git-log-range>]`: checks that every
  hex-hash citation in the commit messages of a range (default
  `origin/master..HEAD`, so only unpushed work) exists as a git object and is
  reachable from `HEAD`, skipping `upstream:`-prefixed ones.  A hash that is
  an object but not an ancestor is the dangerous case: it names a commit
  from an orphaned cherry-pick branch.  Prints `PASS:` or `FAIL:` and exits
  1 on an unreachable citation.

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
