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
  (reachable from HEAD, with `("subject")` annotation, silent), BARE
  (reachable but lacks `("subject")` on the same line within 80 chars —
  ADVISORY if listed in `check-file-content-hash-citations-bare.baseline`,
  FAIL otherwise), DANGLING (exists as a git object but not reachable —
  the dangerous cherry-pick-orphan class, exit 1), or SKIP (not an
  object in this repo — stale external reference or example token,
  counted for auditing but not a failure).  For each DANGLING token the
  gate extracts an adjacent `("subject")` annotation from the same line
  and tries to find a reachable twin via subject match; fallback
  resolution uses `scripts/hash-subject-resolver.sh`.  The bare-citation
  baseline (`check-file-content-hash-citations-bare.baseline`) is a
  descend-only ratchet: fixing a bare citation removes its line from the
  baseline; adding a new bare internal hash is an immediate FAIL.  The
  gate never scans itself or `hash-subject-resolver.sh` to avoid false
  positives from the hex tokens those scripts legitimately contain.
  Complements `commit-msg-hash-resolves` (which checks commit messages)
  by covering the file-content half of the citation convention.
- `check-json-sub-completeness`: for every struct that is JSON-emitted
  via a `stat_category` descriptor table (`STAT_FIELD_SUB` /
  `STAT_FIELD_JSON_SUB` rows), every scalar (non-array) field of that
  struct must appear in at least one descriptor row or bespoke
  `offsetof()` entry.  Closes the gap where a field added to a
  stats/subsys struct and wired to text output silently vanishes from
  the JSON schema; `check-stats-reachable` and `stats-field-unemitted`
  both pass (text consumer counts as reachable) while JSON output is
  incomplete (the failure mode that hid `rtnl_ack_oracle.bad_framing`
  until t489).  Pre-existing gaps are baselined in
  `check-json-sub-completeness.baseline`; that list must shrink, never
  grow.  Array-walked fields and internal bookkeeping are in the script
  static allowlist.
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
  4b5e17517772 ("check-static: gate sfg phase-order invariants") exposed).
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

  **Bucket definition** — the tally covers only syscalls that (a) are
  issued directly in the childop body or a local non-netlink wrapper, and
  (b) represent fuzz surface the childop is exercising as its primary job.
  Three categories are explicitly excluded:

  - *Teardown / cleanup `close()` calls*: resource teardown on error or
    exit paths is infrastructure, not dispatch surface; no childop should
    count it (the convention is dispatch-surface only).
  - *Harness-handshake syscalls* (`pipe`/`read`/`write` used only to
    sequence workers between fork parent and child, or to synchronise
    cooperating threads before the actual work begins): these are
    synchronisation plumbing, not kernel interfaces being fuzzed.
  - *Netlink-proxied syscalls via `caller_op` / `nl_close()`*:
    `nl_close()` already calls `childop_direct_syscalls_add()` internally
    for the netlink transport path; counting those syscalls again in the
    childop body would double-count them in the telemetry.

  The full rationale and authoritative wording live in the header comment
  of `scripts/check-static/childop-direct-syscall-uncounted.sh`.
- `childop-grandchild-this-child`: scan every `.c` file under `childops/`
  for function bodies that (a) assign a local variable from `this_child()`,
  (b) call `_exit(` — the marker of a grandchild-capable worker — and
  (c) access a per-process member (`->MEMBER` where MEMBER is not in the
  fork-invariant set `{op_type, op_nr}`) through that variable.  In a
  fork()'d grandchild `this_child()` returns the COW-inherited parent
  slot; reading or writing per-process state through it corrupts the
  parent's bookkeeping.  See
  `Documentation/this-child-grandchild-reachability.md` for the full
  member classification and the safe/unsafe patterns.
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
- `childop-lock-call`: no `.c` file under `childops/` may call `lock()`
  directly.  `cached_pid` is COW-inherited across `fork()` and never
  refreshed, so it is not process-unique in a grandchild; a grandchild
  that called `lock()` would encode the parent's pid as the lock owner,
  misfire the self-deadlock guard, and block `force_bust_lock()` from
  recovering an orphan.  All 14 `lock()` call sites are on the
  `child_process()` dispatch path and must remain there.  See the
  `bust_lock()` note in `utils/locks.c` for the full audit rationale.
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
- `commit-msg-hash-citations-informal`: scan commit messages of commits
  in `origin/master..HEAD` (falling back to `HEAD~200..HEAD`) and flag
  every hex-hash citation that uses the bare-informal form
  `hash (description text without quotes)` instead of the required
  `hash ("exact commit subject")` form.  Bare-informal citations
  carry wrong attributions when the description is not the real commit
  subject and are invisible to subject-match resolution after a
  cherry-pick rewrite.  Pre-existing violations that cannot be amended
  are baselined by commit SHA in
  `commit-msg-hash-citations-informal.baseline`; any new bare-informal
  citation in a commit not listed in the baseline is a FAIL.
  Complements `check-file-content-hash-citations` (which covers the
  file-content half of the citation convention).
- `commit-msg-hash-resolves`: scan commit messages in
  `origin/master..HEAD` (skipping when there is no unpushed range)
  and FAIL on any hex-hash citation that exists as a git object but is
  NOT reachable
  from HEAD -- a dangling cherry-pick orphan pointing at the wrong
  context.  This is the reachability half of the citation convention,
  complementing the form check in `commit-msg-hash-citations-informal`.
  Pre-existing dangling citations are grandfathered in
  `commit-msg-hash-resolves.baseline`; only a new unreachable citation
  fails.  The gate logic lives in `scripts/commit-msg-hash-resolves.sh`
  (also runnable standalone with an explicit range for manual audits).
- `dead-arm-detect`: warn (WARN, not FAIL) about `.c` files under
  `childops/` and `net/` that use `rnd_modulo_u32()` as a switch
  selector without calling `CHILDOP_ARM_ENTER` in their switch-case
  arms.  A switch arm that never calls `CHILDOP_ARM_ENTER` is invisible
  to the drain-time `DEAD_ARM` reporter in `dump_stats_dead_arm_check()`,
  so a permanently-dead arm looks identical to one that ran and found
  nothing.  Files where `rnd_modulo_u32` is used only for array indexing
  (not multi-arm dispatch) may opt out with a
  `/* dead-arm-detect: not a multi-arm dispatch */` comment.  Tighten
  to FAIL once the `≥19` un-instrumented childops are annotated.
  See `include/arm-tracking.h`.
- `dead-arm-config`: warn (WARN, not FAIL) about childop source files
  whose required build-time or kernel configuration symbol is absent,
  making the arm config-dead on the current build target.  Distinct from
  `dead-arm-detect` (which catches selector-dead arms): a config-dead arm
  either compiles to a stub (`#if __has_include(...)` gate is false) or
  returns `CHILDOP_LATCH_UNSUPPORTED` every invocation because the
  kernel feature is disabled.  Two config sources are probed in order:
  (1) trinity's own `config.h` (generated by `./configure`) for
  `USE_*` symbols, and (2) the running kernel's `/boot/config-$(uname -r)`
  for `CONFIG_*` symbols where trinity has no configure-time gate.
  Confirmed dead arms: `afxdp-churn` / `afxdp-churn-attach`
  (`CONFIG_XDP_SOCKETS` / `USE_XDP`), `thp-split-ref-race`
  (`CONFIG_TRANSPARENT_HUGEPAGE`), and `xfrm-churn`
  (`CONFIG_XFRM_USER`).  Tighten to FAIL once the fuzz-host baseline
  is established.
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
  `dump_stats_json_netfilter_and_xfrm()` (a79d41c36e2b ("stats/json: fix missing comma before ip6mr_churn in network section")^) is replayed
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
  what hides the bug.  Also verifies that each shimmed `XFRMA_*`
  `#define` carries the correct numeric value (the shims are always
  active since `#ifndef` is unconditionally true for enum constants).
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
- `proc-read-eintr-retry`: reject `open()` / `read()` / `pread()` calls
  whose argument list contains a `/proc` path literal, or whose fd
  comes from `pidstatfiles[]`, when not wrapped in
  `TEMP_FAILURE_RETRY`.  Trinity children take `SIGALRM` once per
  second (installed without `SA_RESTART`); an unretried `EINTR` on a
  `/proc` read is treated by callers as "pid is dead", causing false
  reap decisions and silently-dropping D-state diagnostics (`get_pid_state()`
  returns `'?'` instead of `'D'`).  `close()` is deliberately not
  covered: retrying `close()` after `EINTR` on Linux is the
  double-close bug.  Scoped to `main/` + `dispatch/` + `utils/`;
  zero files scanned is treated as FAIL (fail-closed on directory
  renames).
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
- `signal-disposition-ownership`: two checks that guard process-wide
  signal-table state from mutation by childop and mm code.  Check 1
  flags any `signal(sig, SIG_DFL)` call outside `health/` that is
  followed within two source lines by `raise()` — that pattern resets
  the per-signal disposition before delivery and silently bypasses the
  trinity fault beacon (the health fault handler is never entered;
  the child dies bare).  Check 2 flags any `sigaction(SIGSEGV, …)` or
  `sigaction(SIGBUS, …)` install call outside `health/` whose
  translation unit lacks a canonical-read call
  (`sigaction(SIG, NULL, &saved)`) or a saved-disposition variable
  (`_sa_bus` / `_sa_segv`); without the canonical snapshot the
  restore chain may chain to stale state left by a leaked uffd worker.
  Known-acceptable sites are listed in
  `signal-disposition-ownership.allowlist`.
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
- `stats-ring-op-clock-atomic`: every access to `lossless_op_count`
  in production `.c` files (excluding `tests/`) must be lexically
  inside an `__atomic_` call on the same source line.  The parent
  reads the field with `__atomic_load_n`; a plain store or increment
  races with that load and is C11 undefined behaviour regardless of
  whether x86-64 or arm64 codegen happens to be correct today.  Both
  writers must use `__atomic_fetch_add(..., __ATOMIC_RELAXED)`;
  `RELAXED` is correct because the child is the sole writer and
  nothing orders against this counter on either side.
- `u32-skip-sw-oracle-false-positive`: the cls_u32 SKIP_SW update-path
   oracle in `do_u32_skip_sw_leak()` must delete the step-A knode and probe
   hnode2 via `settle_then_probe_hnode2_delete()` (bounded RCU backoff),
   never a direct `RTM_DELTFILTER` on a live hnode2 -- that returns -EBUSY
   on healthy kernels too and is a false positive.  The settle helper must
   be defined, not merely called.
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
- `uapi-shim-values`: every `#define` shim for an enum-backed UAPI constant
  (families: `IFLA_GRE_*`, `IFLA_IPTUN_*`, `NDA_*`) must carry the correct
  decimal value as recorded in `scripts/check-static/uapi-shim-values.baseline`.
  `#ifndef` guards on enum values are always taken — enums are not macros, so
  the shim is the definition, not a fallback.  A miscounted or typo'd value
  compiles silently and sends the wrong netlink attribute to the kernel.
  `XFRMA_*` value correctness is checked in `netlink-xfrm-attr-shim`.
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
- `struct-field-offset-size-wrap`: reject bare `->offset +` arithmetic
  in comparison predicates in `args/` when neither operand carries an
  `(unsigned long)` / `(uint64_t)` cast.  Both `struct struct_field`
  members `offset` and `size` are `unsigned int`; the expression
  `f->offset + f->size` wraps modulo 2^32 before comparison when the
  sum exceeds `UINT_MAX`, silently bypassing the bounds guard.  The
  correct form is `f->offset > size || f->size > size - f->offset`.
  Array-index expressions of the form `buf[f->offset + byte_off]` are
  excluded (the index is bounded by an earlier guard).
