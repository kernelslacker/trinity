# Trinity — Linux System-Call Fuzzer

Trinity fuzzes the Linux syscall ABI. A **parent** process forks a fleet of
**child** processes; each child, in a tight loop, either generates arguments
for one random syscall and issues it, or runs a scripted multi-syscall
"childop" workload. KCOV coverage and KCOV-CMP comparison operands are fed
back to steer argument generation toward new kernel code paths. The parent
never fuzzes — it forks/reaps/watchdogs the fleet and renders telemetry.

This file is the map. Each subdirectory has its own `CLAUDE.md` with the full
detail for that subsystem; the ~40 `.c` files at the repository **root** are
the core runtime and are documented here since they have no directory of
their own.

## Execution model (the loop, top to bottom)

1. `main/trinity.c` — process entry: option parse, table selection, warm-start of
   persisted state, then hands control to the parent control plane.
2. `main/` — the parent tick loop: fork the fleet, poll-reap exits,
   D-state/stuck watchdog, periodic stats. Calls into nothing that fuzzes.
3. `child/` (child.c loop + child-init.c + child-altop.c picker) — each forked child's
   per-iteration loop: pick a syscall **or** an alt-op (childop), run it under
   an `alarm(1)` stall backstop, thread results forward.
4. Per iteration the child either:
   - **random syscall path** — `random_syscall/` picks a syscall number,
     `syscalls/` supplies its descriptor, `args/` + `struct_catalog/` +
     `rand/` + `net/` + `ioctls/` generate the arguments, `dispatch/syscall.c` issues
     the call, `dispatch/results.c`/`kcov/`/`cmp_hints/` record the outcome; or
   - **childop path** — `childops/` runs a scripted stateful sequence
     (churn/race/storm/recipe) against one kernel subsystem.
5. `stats/` aggregates everything the fleet writes into shared memory and the
   parent prints it.

## Subsystem map

| Directory | Role |
|---|---|
| [main/](main/CLAUDE.md) | Process entry + CLI/tunables + parent control plane: fork/reap/watchdog/stats tick loop (6 files, ~6,411 LOC) |
| [child/](child/CLAUDE.md) | Child runtime loop: per-iteration alt-op/syscall pick, canary/sentinel/capdrop oracles, alarm backstop (7 files, ~6,400 LOC) |
| [random_syscall/](random_syscall/CLAUDE.md) | Per-iteration hot path: pick, substitute, dispatch a syscall (5 files, ~4,807 LOC) |
| [dispatch/](dispatch/CLAUDE.md) | Issues the picked syscall, records the result, tracks pid liveness (3 files, ~2,400 LOC) |
| [syscalls/](syscalls/CLAUDE.md) | One `struct syscallentry` descriptor per syscall — the declarative catalog (~361 files, ~56,400 LOC) |
| [tables/](tables/CLAUDE.md) | Loads the per-syscall descriptors into shared memory and stamps derived fields (3 files, ~1,725 LOC) |
| [args/](args/CLAUDE.md) | Argument generation layer driven by `argtype[]` (17 files, ~6,127 LOC) |
| [args/pools/](args/pools/CLAUDE.md) | Argument-content pools feeding the ARG_* generators — pathnames/xattr/blob/devices/blockdevs/fstype (6 files, ~2,237 LOC) |
| [struct_catalog/](struct_catalog/CLAUDE.md) | Static field-level layout catalog for kernel structs (33 files, ~10,289 LOC) |
| [rand/](rand/CLAUDE.md) | Randomness core and scalar value generation (10 files, ~2,923 LOC) |
| [net/](net/CLAUDE.md) | sockaddr / setsockopt / netlink / BPF generation per address family (114 files, ~26,684 LOC) |
| [ioctls/](ioctls/CLAUDE.md) | Per-subsystem `ioctl()` argument generators (59 files, ~14,243 LOC) |
| [fds/](fds/CLAUDE.md) | FD provider layer — where live file descriptors come from (37 files, ~9,123 LOC) |
| [objects/](objects/CLAUDE.md) | OBJ_LOCAL/OBJ_GLOBAL object pools — thread a syscall's result (fd/id/handle) into a later syscall's arg  + cross-child futex pool & prop/fd-event rings (8 files, ~2,732 LOC) |
| [persist/](persist/CLAUDE.md) | Cross-iteration persistence — coverage-guided arg retention (minicorpus) + deferred-free temporal-overlap queue (2 files, ~4,450 LOC) |
| [health/](health/CLAUDE.md) | Signals, crash post-mortem, pre-crash/breadcrumb rings, /dev/kmsg + taint watch — finding-vs-noise triage and crash-report assembly (7 files, ~3,188 LOC) |
| [mm/](mm/CLAUDE.md) | Memory-management fuzzing targets (8 files, ~3,029 LOC) |
| [childops/](childops/CLAUDE.md) | Scripted stateful multi-syscall workloads (churn/race/storm/recipe) (~145 files, ~81,300 LOC) |
| [strategy/](strategy/CLAUDE.md) | Multi-strategy syscall-picker orchestration (7 files, ~3,700 LOC) |
| [kcov/](kcov/CLAUDE.md) | Generic KCOV coverage collection (7 files, ~5,004 LOC) |
| [cmp_hints/](cmp_hints/CLAUDE.md) | KCOV comparison-operand hint system (RedQueen-style) (8 files, ~5,951 LOC) |
| [stats/](stats/CLAUDE.md) | Telemetry aggregation and operator-facing reporting (27 files, ~18,766 LOC) |
| [lib/](lib/CLAUDE.md) | Generic reusable primitives, no shared state (7 files, ~1,457 LOC) |
| [utils/](utils/CLAUDE.md) | General-purpose runtime support (23 files, ~9,181 LOC) |
| [tools/](tools/CLAUDE.md) | Standalone offline socket-cache dump analyzer, not linked into trinity (2 files, ~225 LOC) |

## Root-level core files

These live at the repository root and are compiled directly into the trinity
binary. Grouped by concern:

### Startup & parent orchestration
- [main/](main/CLAUDE.md) — process entry (`main/trinity.c`: `main()`, warm-start, the epoch loop) and CLI/tunable parsing (`main/params/`), alongside the parent control plane (fork/reap/watchdog/stats).

### Child runtime
- [child/](child/CLAUDE.md) — per-child loop, bring-up/sandbox, alt-op picker, canary/sentinel/capdrop oracles, cred throttle (7 files).

### Syscall dispatch & results
- [dispatch/](dispatch/CLAUDE.md) — issues the picked syscall (syscall.c), records results (results.c), pid liveness/kill primitives (pids.c) (3 files).

### Object pools & result threading
- `objects/` — the `OBJ_LOCAL`/`OBJ_GLOBAL` object pools threading a syscall result (fd/id/handle) into a later syscall argument, plus the cross-child futex-word pool and the prop/fd-event rings. See [objects/](objects/CLAUDE.md); `lib/publish_resource.c` is the typed stamping front end.

### Argument content & environment enumeration
- [args/pools/](args/pools/CLAUDE.md) — the content pools the generators draw from: pathname/xattr/blob/device/blockdev/fstype (6 files).

### Persistence & corpora
- [persist/](persist/CLAUDE.md) — coverage-guided argument retention (minicorpus) and the deferred-free temporal-overlap queue (2 files).
- `sequence.c` (1,858) — sequence-aware fuzzing: dispatches short syscall chains, threads each return into the next call's args, plus a chain corpus (held at root during the resource-typing rework; folds into persist/ later).

### Signals, crashes & kernel-health monitoring
- [health/](health/CLAUDE.md) — signal handling + mask policy, crash post-mortem, pre-crash/breadcrumb rings, `/dev/kmsg` scraper and taint-bit watch (7 files).

## Where to start reading

- **To follow one fuzz iteration end-to-end:** `child/child.c` →
  `random_syscall/CLAUDE.md` → `syscalls/CLAUDE.md` → `args/CLAUDE.md` →
  `dispatch/syscall.c` → `dispatch/results.c`.
- **To understand the process fleet / lifecycle:** `main/trinity.c` →
  `main/CLAUDE.md`.
- **To understand scripted (non-random) fuzzing:** `childops/CLAUDE.md`.
- **To understand coverage-guided steering:** `kcov/CLAUDE.md` +
  `cmp_hints/CLAUDE.md` + `minicorpus.c`.

## Notes for editors

- The build uses `$(wildcard ...)` globs — dropping a new `.c` into most
  directories compiles it automatically, but wiring a new *dispatched* childop
  or syscall still requires the manual registration edits documented in
  `childops/CLAUDE.md` and `syscalls/CLAUDE.md`.
- Per-directory `CLAUDE.md` "Areas of attention" sections flag the
  load-bearing invariants and the largest/riskiest files in each subsystem —
  read the relevant one before a non-trivial change.

## Randomness

- Use trinity's helpers from `include/rnd.h`: `rnd_u32()`, `rnd_u64()`,
  `rnd_modulo_u32(N)` (Lemire-debiased), `RAND_BOOL()`, `RAND_RANGE(lo, hi)`,
  `ONE_IN(N)`.
- Never add new `rand()` / `random()` / `drand48()` callsites — libc `rand()`
  is an out-of-line LFSR behind a pthread mutex and shows up at 5%+ in perf on
  hot fuzz paths. Existing callsites are migrating incrementally; leave the
  `srand()` seeding in `rand/seed.c` until every caller has moved.

## uapi gaps

- When a uapi struct or field your code needs isn't in the local headers,
  define a fallback rather than waiting on a header refresh: cross-cutting
  fields → the matching mirror header under `include/kernel/<header.h>`
  (mirroring the kernel header the definition comes from); single-file uses →
  an at-use-site `#ifndef` guard. Shape:
  ```
  #ifndef BPF_F_NEW_FLAG
  #define BPF_F_NEW_FLAG (1U << 17)
  #endif
  ```

## Build & static checks

- The build auto-bumps `include/version.h` GIT_HASH on every `make`. Always
  commit with an explicit pathspec (`git commit <file> …`), never `-a` or
  `git add -A` — those sweep the bumped `version.h` into the commit.
- `make asan` wires `-fsanitize=address -Og -ggdb3`; some allocations and fork
  patterns are gated on `#ifdef __SANITIZE_ADDRESS__` to avoid colliding with
  ASAN's shadow and allocator.
- `make tags` builds a ~0.4s ctags db; regenerate after large changes if
  you'll be grepping.
- Default child count (no `-C`) is pre-tuned for sustained throughput — pass
  `-C` only for deliberate experiments.
- `scripts/check-static/*.sh` enforce invariants via line-numbered baselines. A
  change that shifts lines in a baselined file must update that baseline in the
  same commit (common ones: `child-context-output.baseline`,
  `sanitiser-slow-path.baseline`, `post-state-magic.baseline`).

## Code structure — files & functions

Goal: bounded edit context. Editing one behaviour should page in that
behaviour, not a 5,000-line TU or a 400-line function. Locality of reference,
not aesthetics.

- **Files:** a `.c` over ~1,500 lines, or holding more than one subsystem, is a
  carve candidate → split into `<subsystem>/*.c` (globbed into Makefile
  SRCS+OBJS), cross-cluster state in `include/<subsystem>-internal.h`, public
  header stays in `include/`. A carve is pure code-motion: no logic/rename/
  counter change, one cohesive cluster per commit, each commit passing the full
  gate.
- **Functions:** target ~1–2 screens (~120 lines). Over ~200 lines, or with
  more than one clear responsibility (setup + decision + emit), is an
  extract-method candidate. Signals that beat raw line count: nesting > 4; a
  `switch` arm that's its own algorithm; internal `/* phase N */` dividers.
  Extract cohesive sub-steps into named `static` helpers, one job each, as pure
  code-motion.
- **When not to split:** no 1–3 line helpers (inlining is clearer); don't
  fragment a hot inner loop or a dense correctness boundary to hit a count —
  move it whole and leave a one-line why (a correct 300-line fn beats five that
  fragment an atomic sequence). Don't reflow, rename, or micro-optimise while
  carving — separate commits.
- **When:** refactor code you're already editing, or when it's the explicit
  task. Don't drive-by carve untouched code — it's noise in someone else's
  review and blame.

## Comment style

- Document the *why*, not the *what*.
- **Load-bearing stays** — a comment that justifies a magic constant, states a
  non-obvious invariant, or explains an ordering/TOCTOU/concurrency requirement.
  Aim for signal-per-line, not a line count; never strip rationale to hit a
  target.
- No top-of-file textbook essays — don't reproduce RFCs, kernel struct layouts,
  or a step-by-step that mirrors the code. Cap the file header at ~5 lines:
  intent, the kernel fn/file targeted (once), the key invariant or bug-class.
- History → git log, not inline: CVEs, upstream SHAs, "was X, now Y" go in the
  commit body; inline keeps only the *current* invariant/threshold.
- Don't narrate the next N lines when the names already make the mechanics
  clear. State shared rationale once at the definition and reference it by name.
  Bound `#define` justifications (~3 lines) and syscall-oracle comments (~4
  lines). Remove `/* phase */` and `====` dividers after a carve.

## Codebase gotchas

- **Old multiplexers:** `syscalls/ipc.c` (msgctl/semctl/shmctl) and
  `syscalls/socketcall.c` (the 32-bit socket family) bundle several handlers
  each — a file-grep for one name misses them.
- **Verify kernel API behaviour against the actual kernel source**, don't claim
  it from memory.

## Debugging

- **Memory corruption:** reproduce with `--children 1` first — if a single
  child still corrupts, it's self-corruption, not a sibling shm-stomp; then
  `-c <syscall>` to bisect. The fault site is usually *not* the bug site: a
  handler scribbles a shared pool and an unrelated, more frequent consumer
  later crashes on the stale slot. ASAN only redzones malloc'd heap — it's
  blind to scribbles of trinity's mmap'd shm; use mprotect / guard-pages for
  those.
- **Arg-gen / sanitise testing:** `--dry-run` synthesizes syscall returns and
  gates childops off, so it exercises the arg-gen and sanitise loop without
  touching the kernel. Startup walks all of `/proc` and `/sys` to build the
  pathname pool (slow on a busy host — looks like a hang at init); pass
  `-V <small-dir>` to limit the walk.

## Bug patterns to avoid

- **Gate correctness on the authoritative state, never a separately-maintained
  shadow.** Deciding ownership/presence from a value-keyed mirror (a hash) or a
  counter behind its own fallible `mprotect`, instead of the lock-step source it
  summarizes (`ring[]` / `occupied_mask`), cost two fix rounds (`inflight_hash`,
  then `ring_count`) plus a follow-up. Read the source of truth — shadows
  desync under pressure.
- **Guard unsigned subtraction:** ensure `b <= a` at the point of `a - b`;
  don't rely on an invariant that only held under a prior load/sample order
  (RELAXED or separately-loaded operands can violate it — `frontier_cold_weight`:
  `edges > calls` → underflow to ~ULONG_MAX).
- **Cap any loop that drains/copies an fd or buffer into a log** — an unbounded
  child-stderr memfd drain once materialized a sparse hole into a 1.8 GB log
  (DoS).
- **Use `CLOCK_MONOTONIC` for elapsed time / lifetimes, never `time()` /
  `CLOCK_REALTIME`** (a backward NTP step → negative duration → a spurious
  corruption panic); clamp computed durations to `>= 0`.
- **`memset` a `__user` struct to 0 before setting a subset of its fields**, so
  the kernel never `copy_to_user`s uninitialised bytes (e.g. firewire
  `fw_cdev_get_info`, mtd `usr_oob`).
- **Clamp array access to bounds:** per-syscall loops (especially ones that
  *write* a per-syscall array) clamp to `MAX_NR_SYSCALL`; a bit-position from
  `ctz`/`ffs` of a mask must be masked to the array size before use.
- **Free with the size used to allocate under a size-class allocator**
  (`free_shared_str(p, 80)` matching `alloc_shared_str(80)`, not `strlen+1`) — a
  wrong size strands or corrupts the slab.
- **A published "ready/valid" flag guarding a payload needs RELEASE on the store
  and ACQUIRE on the load, not RELAXED** — otherwise aarch64 readers can see the
  flag set with stale payload.
- **`EINTR`-retry `waitpid` and blocking syscalls** — a single `EINTR` must not
  latch a capability false or leak a zombie on an interrupted reap.
- **`struct_catalog` rows: verify the arg index against the syscall's real
  (1-indexed) signature**, and skip op-multiplexed args (e.g. `futex` a4 is a
  timespec only for the WAIT ops) unless discriminated.
- **Validate that a pointer is a real allocation start before `free()`-ing it.**
  A pointer-shape heuristic (aligned / in user VA / not pid-shaped) still passes
  a heap-region scribble that isn't at an allocation start — libc rejects it as a
  bad free. Track live allocation results (opt-in) for ground truth; opt-in
  rather than every allocation, so direct-free sites don't leave stale entries a
  fuzzed scribble can match.
- **A tick-batched (1-in-N) free/GC loop multiplies effective lifetime by N.**
  Size TTL/lifetime constants against the longest reader window — including a
  reader interrupted by a signal handler that itself ticks the ring — not the
  nominal TTL.
