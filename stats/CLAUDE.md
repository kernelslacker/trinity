# stats/ — Telemetry, Aggregation, and Reporting Subsystem

Central counter collection, aggregation, and dump layer for Trinity. Every other
subsystem (kcov, cmp_hints, childops, random_syscall, corruption defenses)
bumps a counter here; this directory turns those counters into text, JSON,
CSV timeseries, and periodic operator-facing dumps.

## Files (10 files, ~15,946 LOC)

| File | Lines | Role |
|---|---|---|
| stats.c | 2622 | Core: `struct stat_category`/`stat_field` descriptor tables (~150 childop-specific stat blocks), `stats_syscall_category()` classifier, `topn_push()` shared top-N helper, `dump_stats()` top-level shutdown orchestrator |
| dump.c | 3609 | Largest file. Text-render leaf helpers (`dump_stats_render_*`) grouped into ~10 section functions (oracle anomalies, fuzzer subsystems, corruption-and-pool, childop ranked tables, strategy summary, childop-runs-local/network, kcov block) called in sequence from `dump_stats()` |
| json_dump.c | 1921 | `--stats-json` mirror of dump.c: same counters, JSON shape via `stat_category_emit_json()` and hand-written `json_emit_*` section functions; entry point `dump_stats_json()` |
| kcov_cmp.c | 3144 | Deep-dive diagnostics for the cmp_hints/redqueen subsystem: oldpool-vs-shadow A/B, typed-hypothesis (hyp) saturation/state-transition/score-bucket/live-inject blocks, PC-level diag errno table. Periodic entry `kcov_cmp_stats_periodic_dump()` (time-gated, keeps a prev-window snapshot — the one dump cluster *not* carved into pure-render form) |
| periodic.c | 1941 | Parent main-loop tick dumps: `defense_counters_periodic_dump()`, `cost_pool_periodic_dump()`, `top_syscalls_periodic_dump()`, `vma_count_periodic_dump()`, plus `childop_split_dump()` (cumulative childop-vs-random-syscall effort split, also called unconditionally from `dump_stats()`) |
| log.c | 775 | File-handle backing for `--stats-log-file` (human-readable, append-mode) and `--stats-timeseries` (per-window per-syscall CSV); open/close/write lifecycle plus in-child fd-drop hooks |
| runid.c | 611 | Run-identity provenance block: kallsyms SHA + boot_id fingerprint, warm/cold carrier classification, post-warm-load baseline snapshot (`stats_runid_snapshot_start()`) vs shutdown deltas (`stats_runid_render()`), knob-manifest render |
| corrupt_ptr.c | 528 | Attribution dumps for wild-write forensics: per-syscall `range_overlaps_shared()` top-offenders table, burst spike detector (`corrupt_ptr_spike_check()`, called every main-loop tick), per-handler/per-callsite attribution ring dump for `post_handler_corrupt_ptr`, deferred-free reject-by-callsite dump |
| stats-ring.c | 387 | SPSC per-child ring drain: `stats_ring_drain_all()` walks every child's ring once per main-loop iteration, applies deltas to parent-private `struct stats_aggregate`, republishes the `stats_published` mirror page |
| kcov_diag.c | 408 | KCOV per-syscall diagnostic block (descriptor-driven) plus `minicorpus_mut_attrib_canary_check()`, a mid-run cross-check for accidental double-attribution across the `MUT_NUM_OPS` mutation-operator counters |

## Data model

Two parallel counter stores, by design:

1. **`shm->stats`** (kernel-visible shared memory, `include/stats.h`, 5375 lines of
   struct + `STAT_FIELD`/`STAT_CATEGORY` declarations) — the original counter store.
   Hundreds of childop-specific counters (`blob_mutator`, `tcp_ao_rotate`,
   `af_unix_scm_rights_gc`, etc.), each declared once via `STAT_FIELD()` and grouped
   into a `stat_category` with a gate field (block suppressed in dumps if the gate
   counter is 0). Still directly incremented by childops; a wild kernel write via a
   fuzzed syscall arg can scribble these fields, which the corruption-defense layer
   treats as expected/tolerated noise for this class of counter.
2. **`struct stats_aggregate parent_stats`** (stats-ring.c, MAP_PRIVATE, not
   kernel-visible) — the hardened path for hot/security-relevant counters
   (op_count, fault injection, corrupt-ptr attribution, per-syscall CMP attempts,
   syscall-category histogram, successes/failures). Children enqueue deltas into a
   per-child SPSC ring (`enum stats_field` + `aux` sub-index + `delta`,
   `include/stats_ring.h`); the parent is the sole drainer/writer, so a wild kernel
   store can no longer corrupt the authoritative copy directly (it can only corrupt
   a ring slot, which `apply_slot()` validates before touching any array index).
   `struct stats_published` is the small parent-write/child-read mirror subset
   (currently just `fleet_op_count`) that children need for the strategy-rotation
   clock and `syscalls_todo` termination check; mprotected PROT_READ in children
   between publishes.

## Key design decisions

1. **Descriptor-table pattern for counter blocks** — a new childop counter is added
   by declaring the struct member in `stats.h` and appending one `STAT_FIELD()` row;
   `stat_category_emit_text()` / `stat_category_emit_json()` walk the same
   descriptor, so text and JSON output cannot drift from the struct, and there is a
   single edit site instead of three correlated ones.
2. **SPSC ring migration for hot counters** — hot/security-relevant fields moved out
   of `shm->stats` into the ring-fed `parent_stats` aggregate (same ring topology as
   `fd_event_ring`), removing wild-write attack surface for those specific fields
   while leaving the bulk of childop counters on the simpler direct-shm path.
3. **Two-tier dump call graph** — `dump_stats()` (stats.c) is a thin orchestrator
   listing ~20 section calls in fixed order; the actual rendering logic lives in
   dump.c's `dump_stats_render_*` leaf helpers, one per counter cluster. This split
   is the result of a prior code-review pass that carved dump.c, json_dump.c,
   periodic.c, runid.c, corrupt_ptr.c, kcov_diag.c, and log.c out of a single
   original stats.c "verbatim" (each file's header comment documents its carve
   scope and why specific helpers stayed `static` vs became extern via
   stats-internal.h).
4. **kcov_cmp.c intentionally not carved to pure-render** — `kcov_cmp_stats_periodic_dump()`
   gates on elapsed wall time and keeps a prev-window snapshot for delta computation,
   so it has real state, unlike the carved dump clusters; it stays in the
   "core with logic" tier alongside stats.c.
5. **Ring pointer hardening in stats_ring_drain_all()** — before dereferencing a
   child's ring pointer, checks for non-canonical x86-64 addresses (bit 47 pattern)
   and compares against an `expected_stats_rings[]` snapshot captured at init;
   a mismatch is treated as a stomped pointer and the expected value is
   substituted (after the same canonical check) so draining can continue.
6. **corrupt_ptr split across two directories** — `utils/corrupt_ptr.c` holds the
   heuristic detector (`looks_like_corrupted_ptr()`, address-range/PID-collision
   rejection bands); `stats/corrupt_ptr.c` holds only the attribution/reporting
   dumps that consume the counters the detector bumps. Detection and reporting are
   deliberately separate concerns in separate directories.
7. **Own-start delta as the corruption-immune progress metric (runid.c)** — the
   provenance block compares end-of-run counters against a baseline snapshot taken
   after warm-load but before the fuzz loop starts, rather than comparing two
   absolute cache snapshots, closing a stale-cache-key trap where a fully
   productive cold run could look like zero growth against a silently-reused warm
   cache.

## Integration points

- `main/main.c` `run_periodic_surfaces()` — per-tick driver: calls
  `corrupt_ptr_spike_check()`, `defense_counters_periodic_dump()`,
  `cost_pool_periodic_dump()`, `top_syscalls_periodic_dump()`,
  `vma_count_periodic_dump()`, `kcov_cmp_stats_periodic_dump()` every main-loop
  iteration; each callee is internally rate-limited/self-gated.
- `trinity.c` — calls `dump_stats()` once at shutdown; this is the sole entry point
  for the full text/JSON report.
- `stats/stats-ring.c` `stats_ring_drain_all()` — called once per main-loop
  iteration to drain every live child's SPSC ring into `parent_stats`; producers of
  ring slots are spread across `deferred-free.c`, `syscall.c`, `child.c`,
  `signals.c`, `utils/heap_bounds.c`, `utils/corrupt_ptr.c`,
  `utils/range_overlap.c`, `childops/fault-injector.c`, `kcov/lifecycle.c`,
  `cmp_hints/get.c`, `rand/random-address.c`, `syscalls/{unshare,clone,clone3}.c`.
- `kcov/` — feeds `shm->stats` kcov counters (edges, PCs, dedup, warm-known-hits)
  that dump.c's `dump_stats_kcov_block()` and json_dump.c's `json_emit_kcov_*`
  render; `kcov/lifecycle.c` also enqueues ring deltas.
- `cmp_hints/` — `stats/kcov_cmp.c` is effectively a dedicated diagnostic front-end
  for the cmp_hints/redqueen hypothesis engine (oldpool-vs-shadow, hyp state
  machine, live-inject reasons); consumes counters bumped throughout
  `cmp_hints/collect.c`, `cmp_hints/hyp.c`, `cmp_hints/credit.c`. `cmp_hints/get.c`
  also enqueues ring deltas for try-get attempts/returns.
- `random_syscall/pickers.c` — feeds the per-syscall CMP-insert counters that
  dump.c's "Top syscalls by CMP inserts" table renders.
- `strategy/strategy-stats-dump.c` — separate operator summary, called from
  `dump_stats()` at end of run alongside this directory's own sections.
- `child-altop.c` — `childop_score_dump()` and `childop_outcome_window_dump()` are
  defined there but invoked from `stats.c`'s `dump_stats()`, and
  `defense_counters_periodic_dump()` documents a driven-from relationship back into
  child-altop.c's permille dump.
- `childops/recipe-runner.c`, `childops/iouring-recipes.c` — expose their own
  `*_dump_stats()` entry points, called from dump.c as sibling blocks.
- `include/stats.h`, `include/stats-internal.h`, `include/stats_ring.h` — the three
  headers this directory is built around: `stats.h` (5375 lines) holds every
  `STAT_FIELD`/`STAT_CATEGORY` declaration plus `shm->stats` struct layout;
  `stats-internal.h` exposes the carved-out dump helpers as externs across the 8
  implementation files; `stats_ring.h` defines `enum stats_field`, the ring slot
  layout, and `STATS_RING_SIZE` (1024 slots, 16 KiB/ring).

## Areas of attention

1. **stats.c and dump.c are both oversized for their nominal role.** stats.c is
   ~1450 lines of nothing but `STAT_FIELD`/`STAT_CATEGORY` table declarations (one
   block per childop) before `dump_stats()` even appears; dump.c is 3609 lines of
   ~80 leaf `dump_stats_render_*` functions. Neither is unreasonable individually
   (mechanical, repetitive, low-risk-per-line) but a new childop counter or dump
   section has no natural smaller home to land in — everything funnels into these
   two files.
2. **kcov_cmp.c (3144 lines) is the single largest "does actual work" file** in the
   directory — it is not a pure carve-out like the others and mixes stateful
   time-gated periodic logic with ~20 distinct render blocks for the hypothesis
   engine. Any bug here is harder to localize than in the mechanically-generated
   dump.c/json_dump.c leaf functions.
3. **Two independent counter stores with different corruption guarantees** —
   `shm->stats` fields remain directly writable by a wild kernel store; only the
   subset migrated to the SPSC-ring-fed `parent_stats` aggregate is hardened. A
   contributor adding a new "security-relevant" counter must know to route it
   through `stats_ring_enqueue()` rather than bumping `shm->stats` directly, and
   nothing enforces that choice at compile time.
4. **Ring pointer canary/canonical checks in `stats_ring_drain_all()`** guard
   against a documented real-world failure (a D-state zombie waking after its slot
   was recycled, observed producing a non-canonical pointer in the wild per the
   inline comment) — this is a live hardening concern, not speculative.

## Summary

Counters are produced almost everywhere in the codebase (childops, kcov, cmp_hints,
corruption defenses, random_syscall) and converge here through two paths: the bulk
of childop-specific counters land directly in kernel-visible `shm->stats` and are
rendered via a shared `STAT_FIELD`/`STAT_CATEGORY` descriptor table; a smaller set
of hot/security-relevant counters route through per-child SPSC rings into a
parent-private hardened aggregate. `dump_stats()` (shutdown) and five periodic
dump entry points (main-loop tick, independently rate-limited) are the only
consumers that turn either store into operator-visible output — text, `--stats-json`,
`--stats-log-file`, or `--stats-timeseries` CSV.
