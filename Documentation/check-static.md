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

- `activate-syscall-active-flag`: every direct `activate_syscall*()`
  callsite must first set the entry's ACTIVE flag, so the flag-driven
  init / dump / picker consumers see the activated entry.
- `bpf-opcode-shim`: every `BPF_*` symbol used in `net/bpf/*.c` must be
  `#define`d by trinity's uapi-shim headers (`include/bpf.h`,
  `net/bpf/internal.h`) or listed in `bpf-opcode-shim.baseline`.  A newly
  used ISA opcode with no `#ifndef` fallback builds where
  `<linux/bpf.h>` is new enough but breaks where it is older; this makes that
  a build-time failure instead of a late surprise.  The baseline holds
  base-UAPI symbols relied on from the system header.
- `bpf-subcmd-catalog`: every `BPF_*` subcommand in `bpf_cmds[]`
  (`syscalls/bpf.c`) must have a matching `.discrim_value` entry in
  `bpf_attr_variants[]` (`struct_catalog/bpf.c`), or the sanitiser
  falls through to the empty shared prefix and the fuzzer reverts to
  blind width-guessing for that subcmd.  Pre-existing gaps are
  grandfathered in `bpf-subcmd-catalog.baseline`; the baseline should
  shrink over time, never grow.
- `check-alt-op-rotation`: every `CHILD_OP_*` referenced from
  `pick_op_type_table[]` must be reachable via `alt_op_rotation[]` or
  explicitly listed in `alt-op-rotation.denylist` with a reason.
- `check-file-content-hash-citations`: scan every tracked
  `Documentation/*.md` and `scripts/**/*.sh` file for bare hex tokens
  (12–40 chars, at least one `[a-f]` digit) and classify each as FOUND
  (reachable from HEAD, silent), DANGLING (exists as a git object but
  not reachable — the dangerous cherry-pick-orphan class, exit 1), or
  SKIP (not an object in this repo — stale external reference or example
  token, counted for auditing but not a failure).  For each DANGLING
  token the gate extracts an adjacent `("subject")` annotation from the
  same line and tries to find a reachable twin via subject match;
  fallback resolution uses `scripts/hash-subject-resolver.sh`.  The
  gate never scans itself or `hash-subject-resolver.sh` to avoid
  false positives from the hex tokens those scripts legitimately
  contain.  Complements `commit-msg-hash-resolves` (which checks commit
  messages) by covering the file-content half of the citation convention.
- `check-option-off-branch-inert`: every long option in
  `main/params/*.c` whose parser accepts `"off"` must have an inert
  off-branch body -- a direct assignment to an `*_OFF` enum whose
  value equals 0, so the branch consumes no RNG draw and lands on
  state bit-equal to the zero-initialised default.  This pins the
  structural floor beneath the "byte-identical A/B" runtime claims
  in `help.c` before the picker migrates onto arena test infra.
- `check-option-parity`: every long option in
  `main/params/options.c::longopts[]` must be (a) unique in the
  table, (b) reached by a parser case in `main/params/*.c`, (c)
  documented in `help.c::option_descs[]` or a `Documentation/*.md`
  file, and (d) backed by a default in `state.c` / `defaults.c` or a
  subsystem-owned source.  Drift shows up on-host as "option accepted
  but does nothing" or "internal error: unhandled long option --NAME";
  this gate catches it before a fuzz host does.
- `check-periodic-text-schema`: pin the block-header and counter-name
  schema of the parent-side periodic text surfaces emitted by
  `main/loop.c::run_periodic_surfaces()` (`counter-rates`,
  `childop-split`, `cost-pool`, `top-syscalls`, `vma`, `strategy-topn`)
  against a golden baseline, so rename / removal / reorder never
  silently reshapes the surface downstream operator tooling greps.
  Regenerate with `--regen` and review the baseline diff.
- `check-reexec-coverage`: every `struct syscallentry` block in
  `syscalls/**/*.c` that has a `.sanitise =` field must carry one of:
  `REEXEC_SANITISE_OK` (static flag), a `/* Not REEXEC_SANITISE_OK: */`
  rejection comment, `AVOID_REEXEC`, or be listed in
  `check-reexec-coverage.baseline` as a known-dynamic entry that
  publishes `REEXEC_OK` per-invocation.  Catches a new sanitise-bearing
  entry added without annotation — a gap the existing file-level grep
  cannot see.
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
- `check-static-doc-parity`: every script in `scripts/check-static/`
  must have a matching row in this file, and every row here must
  correspond to a real script.  A new check landing with no doc row
  fails the gate; a stale row for a removed check fails it in the
  other direction.  This gate exists because the "What today's checks
  enforce" list is hand-maintained -- without enforcement, it drifted
  silently until 22 scripts were undocumented at once (the state
  4b5e17517772 exposed).
- `check-stats-reachable`: every scalar counter reachable from
  `struct stats_s` (flat leaves plus recursively-descended
  `stats/subsys/*_stats` sub-structs) must be surfaced by a
  `STAT_FIELD*()` descriptor row, a bespoke `offsetof(...)` emitter
  row, or a consumer-side `shm->stats.<path>` read that is NOT itself
  a producer write / mutating `__atomic_*`.  Catches the dead-counter
  class where a field is bumped but never rendered, indistinguishable
  from a broken strategy from the outside.  Allowlist is tuned so
  today's tree passes; new dead counters trip.
- `child-context-output`: flag `output()` / `outputerr()` /
  `outputstd()` calls reachable from child-context code (`.post`
  handlers and `childops/*.c`), where they vanish into the child's
  /dev/null'd stdio.
- `child-exit-zero-error-path`: flag `_exit(0)` callsites in
  child-context source (`childops/*.c`, `syscalls/*.c`, `child.c`,
  `kcov.c`) whose preceding ~10 lines contain failure-branch tokens
  (`perror`, `output_err`, `warn`, `fatal`, `abort`, `goto err*`,
  `goto fail*`, or a `case` label naming `err`/`fail`/`abort`/
  `recovery_exhausted`).  Such an exit is invisible to
  `reap_entry_is_fast_die()` and silently neutralises the fork-storm
  fast-die breaker; the fix is `_exit(<sentinel>)` with a non-zero
  code.  Genuine happy-path callsites that over-fire the heuristic
  are pinned in `scripts/check-static/child-exit-zero-error-path.baseline`;
  that list should shrink over time, never grow.
- `childop-direct-syscall-uncounted`: every childop translation unit
  that issues raw syscalls in its own body (via `trinity_raw_syscall()`,
  `trinity_cmp_syscall()`, `socket()`, `sendmsg()`, `sendto()`,
  `setsockopt()`, `mmap()`, or `syscall()`) must call
  `childop_direct_syscalls_add()` so those calls appear in the
  direct-syscall telemetry bucket.  Files whose netlink path is already
  counted by `nl_close()` (which calls `childop_direct_syscalls_add()`
  internally when `caller_op` is set) are grandfathered in
  `scripts/check-static/childop-direct-syscall-uncounted.baseline` if
  their additional own-body calls are not yet wired; that list should
  shrink over time, never grow.
- `childop-stats-writer-registered`: every `.c` file under `childops/`
  that writes `shm->stats.*` counters must have a corresponding
  `CHILD_OP_*` entry in `include/childop.def` whose dispatch function is
  defined in that file, or be listed in
  `scripts/check-static/childop-stats-writer-registered.baseline` as a
  carve file (called from a sibling's registered dispatch entry point)
  or shared infrastructure unit.  A file that writes stats counters but
  defines no registered dispatch function and has no baseline exemption
  is dead code -- its producers never execute and every counter stays
  zero.  The baseline should shrink over time, never grow.
- `cmp-hints-canonicalise-cmp-ip`: (i) `kcov_canon_cmp_ip()` in
  `kcov/collect.c` must subtract `kcov_kaslr_base`, and (ii) every
  function in `cmp_hints/cmp_hints.c` that calls
  `cmp_hints_bloom_check_and_set()` or `pool_add_locked()` must also
  call `kcov_canon_cmp_ip()` in the same body -- otherwise raw cmp_ip
  values enter the bloom / per-syscall pool and warm-loaded pools
  silently alias fresh runs across KASLR rerolls of the same kernel
  build.  Companion to `kcov-canonicalise-pcs` on the PC side;
  `cmp_hints_flush_pending()` is the one whitelisted transitive
  caller because its inputs are already canonical.
- `doc-pointer-exists`: every flat `Documentation/<name>.md` path named
  in a code comment must resolve to a real file, so the one-line
  pointers that replaced carved-out design essays never dangle.
  Kernel-tree references (`Documentation/<subdir>/...`) are out of
  scope -- they point outside this repo.
- `fd-event-close-direct`: every producer of `FD_EVENT_CLOSE` outside
  `fd-event.c` must go through the canonical
  `notify_child_fd_closed[_range]()` helper to preserve the close
  contract.
- `fd-from-object-coverage`: `fd_from_object()` in `objects/dispatch.c` must
  switch on every `OBJ_FD_*` enum value, and every case label must
  still refer to a live enum member.
- `io-uring-register-catalog`: every opcode in
  `io_uring_register_opcodes[]`
  (`syscalls/io_uring/io_uring_register.c`) must have a matching
  `.discrim_value` entry in `io_uring_register_variants[]`
  (`struct_catalog/io_uring_register.c`), or the sanitiser has no
  per-opcode schema and the fuzzer reverts to blind width-guessing.
  Pre-existing gaps are grandfathered in
  `io-uring-register-catalog.baseline`; the baseline should shrink
  over time, never grow.
- `ioctl-struct-memset`: every `get_writable_struct(sizeof(*var))`
  call in `ioctls/*.c` that allocates a `struct`-typed chunk must be
  followed within a small window by `memset(var, 0, ...)` before the
  first field store.  Without the zero-fill, the pool residue left
  behind by a previous user leaks into the ioctl payload the kernel
  reads (or copies back to userspace) -- fuzz-time false signal
  masquerading as kernel signal.  Anonymous / primitive allocations
  are skipped; genuine field-by-field-writes exceptions go on the
  `IGNORE` list with a justification.
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
  `dump_stats_json_netfilter_and_xfrm()` (a79d41c36e2b^) is replayed
  inline as a known-bad input and must produce exactly one hit.
- `kcov-canonicalise-pcs`: (i) `kcov_canon_pc()` in `kcov/collect.c`
  must subtract `kcov_kaslr_base`, (ii) `pc_canon_to_edge()` must
  NOT re-invoke `kcov_canon_pc()` (a canon-in helper that
  double-canonicalises masks caller bugs), and (iii) every function
  in `kcov.c` reaching `pc_canon_to_edge()` must also call
  `kcov_canon_pc()` in the same body -- otherwise raw runtime PCs
  reach the edge/transition slot hash and the cached bitmap silently
  aliases across KASLR rerolls the fingerprint considers identical.
- `nested-writable-len`: flag nested `get_writable_struct` /
  `get_writable_long_string` allocations stored straight into an outer
  struct field without a NULL check -- the NULL-pointer-with-nonzero-
  length ioctl bug class.
- `net-proto-sfg-parity`: cross-check the two PF-indexed net dispatch
  tables -- `net_protocols[]` in `net/protocols.c` (used by
  `sfg_default_bind()` / `sfg_default_pick_triplet()`) and
  `sfg_registry[]` in `net/socket-family-grammar-core.c` (the
  per-family grammars).  A grammar registered for a PF with no
  netproto entry is a NULL-deref waiting to happen and fails
  unconditionally; the reverse direction (netproto with no grammar)
  is silent-coverage drift, grandfathered in
  `net-proto-sfg-parity.baseline`.
- `netlink-xfrm-attr-shim`: every `XFRMA_*` token used in
  `net/proto/netlink-xfrm*.c` must be `#define`d in the fallback
  `#ifndef` block of `include/proto-netlink-xfrm-internal.h`.  A new
  attribute with no fallback builds against a new-enough
  `<linux/xfrm.h>` and breaks against an older one; the local header
  is the ownership boundary because trusting the system header is
  what hides the bug.
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
- `pdeathsig-getppid-recheck`: every `prctl(PR_SET_PDEATHSIG, ...)`
  arming callsite in child code (`childops/*.c`, `syscalls/*.c`
  excluding `syscalls/prctl.c`, `child.c`) must be followed within
  the same function body by a `getppid()` (or raw
  `syscall(__NR_getppid)`) re-check before the next blocking call.
  Without it, a parent that dies in the window between `clone3()`
  returning in the child and the prctl landing leaves the child
  reparented under PID 1, blocked forever in `pause()` /
  `raw_futex_wait()`.  Grandfathered callsites the heuristic
  over-fires on are pinned in
  `scripts/check-static/pdeathsig-getppid-recheck.baseline`; that
  list should shrink over time, never grow.
- `perf-event-attr-catalog`: tripwire that grep-asserts the 8
  annotated scalar fields plus the off-40 hand-built bit-field group
  in `perf_event_attr_fields[]` (`struct_catalog/perf.c`) still carry
  the expected `FT_ENUM` / `FT_FLAGS` / `FT_VERSION_MAGIC` tags.  No
  runtime path consumes the tags today (they are forward infra for
  type-scoped CMP attribution), so a wrong tag silently demotes CMP
  scope without breaking build or test -- this check is the drift
  guard.
- `post-double-publish`: a `.post` handler must not call both a
  `register_*` and a `publish_*` helper on the same object -- the
  syscall return path already registers, so a post-side publish
  enrolls the object twice.
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
- `rettype-multiplexer-conflict`: an op-multiplexed syscall (one whose
  `.sanitise` publishes `rec->rettype` per-cmd) must not also carry a
  static `.rettype = RET_XXX` initializer.  `effective_rettype()`
  short-circuits on any non-`RET_NONE` `entry->rettype`, so a static
  stamp silences the per-cmd contract for every downstream consumer
  (fd-group `live_fds` tracking, retfd corruption guard, RZS blanket
  gate, `validate_ret_bound()`).  Files that declare
  `.rettype_publish_hint` are exempt -- that field lets static
  walkers still classify the entry without stamping a real rettype.
- `sanitiser-slow-path`: forbid hot-path slow-syscall callsites
  (`/proc/self/maps`, `fopen`/`getline`, `mincore`/`mprotect` probes)
  in the per-syscall sanitiser / argument-generation file set.
- `sfg-phase-order-invariants`: for every `struct sfg_phase_order`
  initializer in the tree, assert the six phase-order invariants the
  `run_grammar_chain` walk relies on -- SOCKET first, BIND before
  LISTEN, LISTEN before ACCEPT, DATA only after ACCEPT, PRE_CFG
  before BIND, POST_CFG after BIND.  Conditional rules are gated on
  "both phases present" so tables using a disjoint phase vocabulary
  (AF_ALG's `SFG_PHASE_ALG_*`) satisfy them vacuously.
- `shared-region-budget`: tripwire that warns when the number of
  shared-region producer call sites approaches `MAX_SHARED_ALLOCS`.
  Silent under-protection is the bug class, not loud over-protection.
- `shm-latch-direct`: latch fields of `struct shm_s` (`exit_reason`,
  `current_strategy`, `current_selection_reason`,
  `plateau_current_hypothesis`) must only be read or written through
  `__atomic_*` intrinsics; a plain `shm->field` access is a torn write
  that breaks the publish ordering.
- `siginfo-catalog`: every `SI_*` value in
  `siginfo_t_si_code_vocab[]` (`struct_catalog/signal.c`) must have a
  matching variant discriminator in `siginfo_t_variants[]` (either a
  single `.discrim_value = SI_*` or a member of a
  `.discrim_values = *_discrim_values[]` array), or the sanitiser
  has no per-si_code schema and the fuzzer reverts to blind
  width-guessing.  Pre-existing gaps are grandfathered in
  `siginfo-catalog.baseline`; the baseline should shrink over time,
  never grow.
- `signal-handler-async-unsafe`: forbid async-signal-UNSAFE libc calls
  (`snprintf`, `malloc`, `fopen`, `syslog`, ...) inside known signal
  handlers discovered in `signals.c`.
- `sockaddr-af-catalog`: every `AF_*` value in
  `sockaddr_storage_af_vocab[]` (`struct_catalog/sockaddr-af.c`) must
  have a matching `.discrim_value` entry in
  `sockaddr_storage_variants[]`, or the sanitiser has no per-AF
  schema and the sockaddr payload past `ss_family` stays opaque
  (with `msg_namelen` reporting the full envelope size instead of
  the per-AF struct size).  No baseline -- the two arrays are
  curated in lock-step in the same file.
- `srec-no-lock-around-publish`: flag any `lock(&...->lock)`
  immediately preceding a `srec_publish_begin(...)` or any
  `unlock(&...->lock)` immediately following a `srec_publish_end(...)`
  (with at most a blank line / single comment in between).  The srec
  publish brackets are a self-sufficient writer-side ordering anchor;
  re-adding the `rec->lock` pair around them reintroduces the very
  lock the strengthening commit set out to remove.
- `stats-field-unemitted`: every field declared in `stats/subsys/*.h`
  must be referenced by at least one emitter in `stats/` -- via a
  direct struct member access in `stats/json/`, `stats/dump/`, or a
  periodic / shutdown reporter under `stats/*/`, or a
  `STAT_FIELD_SUB(subsys, field)` entry in the matching
  `stats/subsys/*.c` descriptor table.  A field with a live producer
  (atomic add in a childop or strategy file) but no emitter accrues
  silently and is invisible to operators reading `--stats-json` or a
  periodic dump.  Fields that are intentionally internal
  (window-start snapshots, scheduler hysteresis state, per-syscall
  arrays too wide for flat JSON) are grandfathered in
  `scripts/check-static/stats-field-unemitted.baseline`; that list
  should shrink over time, never grow.
- `stats-json-schema`: pin the structural shape of the `--stats-json`
  document -- key-path + value-type in emission order, with
  descriptor-driven `STAT_FIELD*()` keys folded in and nested
  key paths (e.g. `stats.fault_injection.armed_fail_nth`) preserved
  -- against a golden baseline.  Catches renamed keys, retyped
  values, reordered emission, and duplicate keys at the same scope
  that would otherwise silently break downstream scrapers.
  Regenerate with `--regen` and review the baseline diff.
- `syscall-metadata`: best-effort sanity on `struct syscallentry` --
  ARG_RANGE arguments must declare low/high bounds.
- `tipc-addrtype-catalog`: every `TIPC_ADDR_*` value in
  `tipc_addrtype_vocab[]` (`struct_catalog/sockaddr-af.c`) must have
  a matching `.discrim_value` entry in
  `sockaddr_tipc_addr_nested[]`, or the sanitiser has no per-arm
  schema for the inner addr union and its u32 sub-fields never gain
  the tagged-union annotations the catalog was meant to hang off
  them.  No baseline -- the two arrays are curated in lock-step in
  the same file.
- `track-shared-region-pairing`: every `track_shared_region()` must
  have a matching `untrack_shared_region()` on every cleanup-goto exit
  path that can free or recycle the backing mapping.
- `valid-op-stat-guards`: flag two adjacent `if (valid_op)` guards
  in `childops/*.c` where the first body writes
  `childop_setup_accepted[op]` and the second writes
  `childop_data_path[op]`.  The accept-then-progress pair belongs
  under a single guard; splitting them re-evaluates the bounds check,
  drops a compiler barrier between two accounting-only stores, and
  skews the counters apart if the guard ever grows side-effects.
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
