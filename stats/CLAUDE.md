# stats/ - Telemetry, Aggregation, and Reporting Subsystem

Central counter collection, aggregation, and dump layer for Trinity. Most
subsystems (kcov, cmp_hints, childops, random_syscall, corruption defenses)
bump counters here; this directory turns those counters into text, JSON, CSV
timeseries, and periodic operator-facing dumps.

## Layout (35 implementation files)

| Path | Role |
|---|---|
| stats.c | Shutdown report orchestrator. `dump_stats()` owns section order only. |
| common.c | Shared helpers: text-PC check, op names, row printer, top-N insert. |
| category.c | `stat_category` value loads and shared text-category renderer. |
| categories/base.c | Core/blob/oracle/staged descriptor tables. |
| categories/childop.c | Local childop descriptor tables. |
| categories/network.c | Network childop descriptor tables. |
| dump.c | Empty compatibility TU; text dump leaves live in subdirectories. |
| dump/syscall.c | Runtime header, syscall category histogram, per-syscall summary tables, wedge top-Ns. |
| dump/fd.c | FD lifecycle/provider summaries. |
| dump/shared-buffer.c | Shared-buffer misc and range-overlap offender summary. |
| dump/oracle.c | Oracle anomaly counters. |
| dump/subsystems.c | Fuzzer subsystem counters and recipe-owned stats hooks. |
| dump/corruption.c | Corruption, deferred-free, pool, and paired-fd diagnostics. |
| dump/strategy.c | Strategy, plateau, picker, and per-syscall CMP-insert summaries. |
| dump/corpus-tail.c | Minicorpus, cmp_hints, taint, and late tail summaries. |
| childop/local.c | Local childop run rows, decay recency, fd-delta, and topology-pair shadow dumps. |
| childop/ranked.c | Ranked childop tables: wall time, edges, util, skips, wedges. |
| network/childops.c | Network childop aggregate sections. |
| kcov/dump.c | Shutdown KCOV coverage and comparison diagnostics block. |
| json/dump.c | `--stats-json` top-level orchestrator: root object, `"stats"` wrapper, and section order. |
| json/common.c | JSON mechanics: string escape and `stat_category_emit_json()` descriptor renderer. |
| json/syscalls.c | Per-syscall JSON array. |
| json/kcov.c | KCOV JSON block (counters, transition globals, top-Ns, cold syscalls, previous-window snapshots). |
| json/minicorpus.c | Minicorpus JSON block (mutators, xprop, stack-depth, saves/evicts, replay-wins, sequence chains). |
| json/cmp-hints.c | cmp_hints JSON summary (total hints, syscalls-with-hints). |
| json/core.c | Non-network JSON section emitters + basic-subsystem descriptor tables. |
| json/network.c | Network / netfilter / xfrm / socket-family / long-chain JSON section emitters + descriptor tables. |
| json/tail.c | iouring-zc / KVM / nl80211 / NAT-T / AF_ALG / probes-misuse hand-written tail. |
| kcov_cmp.c | Stateful periodic cmp_hints/redqueen diagnostics and previous-window deltas. |
| periodic/strategy-topn.c | Shadow strategy per-syscall top-N helpers called at shutdown from `dump/strategy.c`. |
| periodic/counter-rates.c | `defense_counters[]` rate table + `defense_counters_periodic_dump()` parent-tick emitter. |
| periodic/childop-split.c | Childop-vs-random-syscall walltime/syscalls/iterations split emitter. |
| periodic/cost-pool.c | Cost-pool active-count + shadow/live selector-fraction snapshot. |
| periodic/top-syscalls.c | Per-syscall bandit/explorer/frontier/RQ/warm-reserve top-N deltas. |
| periodic/vma.c | Parent + child `/proc/*/maps` line-count snapshot for VMA-leak triage. |
| log.c | `--stats-log-file` and `--stats-timeseries` file lifecycle. |
| runid.c | Run identity, boot/cache provenance, and shutdown delta manifest. |
| corrupt_ptr.c | Corrupt-pointer attribution and deferred-free reject reporting. |
| stats-ring.c | Per-child SPSC ring drain into parent-private aggregates. |
| kcov_diag.c | Descriptor-driven KCOV per-syscall diagnostic helpers. |

## Data Model

Two parallel counter stores, by design:

1. **`shm->stats`** (kernel-visible shared memory, `include/stats.h`) - the
   original counter store. Hundreds of childop-specific counters are declared
   once via `STAT_FIELD()` and grouped into `stat_category` tables under
   `stats/categories/`. Childops still increment most of these directly; a wild
   kernel write via a fuzzed syscall arg can scribble these fields, which the
   corruption-defense layer treats as expected noise for this class of counter.
2. **`struct stats_aggregate parent_stats`** (`stats-ring.c`, MAP_PRIVATE, not
   kernel-visible) - the hardened path for hot/security-relevant counters
   (op count, fault injection, corrupt-ptr attribution, per-syscall CMP
   attempts, syscall-category histogram, successes/failures). Children enqueue
   deltas into a per-child SPSC ring (`enum stats_field` + `aux` + `delta`,
   `include/stats_ring.h`); the parent is the sole drainer/writer, so a wild
   kernel store can no longer corrupt the authoritative copy directly.

## Key Design

1. **Descriptor tables by domain** - a new direct-shm counter is added by
   declaring the struct member in `stats.h` and appending one `STAT_FIELD()`
   row to the matching file in `stats/categories/`. Text and JSON renderers
   both walk the descriptors, so they cannot drift from the struct layout.
2. **SPSC ring for hardened counters** - hot/security-relevant fields move
   through `stats_ring_enqueue()` into `parent_stats`. A contributor adding a
   new security-relevant counter should choose this path rather than direct
   `shm->stats` writes.
3. **Section-oriented text dump** - `dump_stats()` in `stats.c` lists the fixed
   shutdown report order. Leaf renderers live under `stats/dump/`,
   `stats/childop/`, `stats/network/`, and `stats/kcov/`, so a new section has
   a natural smaller home.
4. **Stateful periodic logic stays separate** - `kcov_cmp.c` keeps elapsed-time
   gates and previous-window snapshots for cmp_hints/redqueen diagnostics; it is
   intentionally not a pure shutdown-render file.
5. **Ring pointer hardening in `stats_ring_drain_all()`** - before dereferencing
   a child's ring pointer, the drainer checks for non-canonical x86-64 addresses
   and compares against an `expected_stats_rings[]` snapshot captured at init.

## Integration Points

- `main/main.c` `run_periodic_surfaces()` calls the rate-limited periodic
  surfaces: corrupt-pointer spike check, defense counters, cost pool, top
  syscalls, VMA count, and cmp_hints periodic diagnostics.
- `main/trinity.c` calls `dump_stats()` once at shutdown; this is the sole entry
  point for the full text/JSON report.
- `stats/stats-ring.c` `stats_ring_drain_all()` drains each live child's SPSC
  ring into `parent_stats` once per parent main-loop iteration.
- `kcov/` feeds KCOV counters rendered by `stats/kcov/dump.c` and JSON KCOV
  sections in `stats/json/kcov.c`; `kcov/lifecycle.c` also enqueues ring deltas.
- `cmp_hints/` feeds the periodic front-end in `stats/kcov_cmp.c`; top
  per-syscall CMP insert rows in the shutdown report are rendered from
  `stats/dump/strategy.c` and `stats/kcov/dump.c`.
- `strategy/strategy-stats-dump.c` provides a separate operator summary called
  from `dump_stats()` alongside the stats-owned sections.
- `child-altop.c` owns `childop_score_dump()` and
  `childop_outcome_window_dump()`; `dump_stats()` invokes them as part of the
  childop block.
- `childops/recipe-runner.c` and `childops/iouring-recipes.c` expose
  `*_dump_stats()` entry points called from `stats/dump/subsystems.c`, keeping
  recipe catalog layout private to the recipe implementations.
- `include/stats.h`, `include/stats-internal.h`, and `include/stats_ring.h` are
  the three headers this directory is built around: shared-memory counter
  layout, private cross-file stats interfaces, and ring slot definitions.

## Areas of Attention

1. **`kcov_cmp.c` is still the largest stateful file** - it mixes time-gated
   periodic state with many render blocks for the hypothesis engine. Bugs here
   are harder to localize than in the pure shutdown render leaves.
2. **`stats/kcov/dump.c` is the largest pure-render file** - it is mechanically
   grouped around the shutdown KCOV block, but future KCOV-only edits should
   consider another domain split before it grows further.
3. **JSON descriptor ownership is still mixed** - `stats/json/` now mirrors
   the text-dump layout (common, syscalls, kcov, minicorpus, cmp-hints,
   core, network, tail, dump), but `stats/json/network.c`, `stats/json/core.c`,
   and `stats/json/tail.c` still own JSON-local descriptor tables that would
   more naturally live under `stats/subsys/` or `stats/categories/`.  Follow-up
   work should migrate one domain at a time, keeping schema order unchanged.
4. **Counter-store choice is still manual** - direct `shm->stats` fields remain
   writable by a wild kernel store; only the ring-fed `parent_stats` aggregate is
   hardened. Review new counters for whether they are telemetry or authoritative
   control/diagnostic state.
5. **Ring pointer hardening is load-bearing** - the canonical-address and
   expected-pointer checks in `stats_ring_drain_all()` cover an observed recycled
   child-slot failure mode, not a theoretical cleanup.

## Summary

Counters are produced across the codebase and converge here through two paths:
bulk childop telemetry lands directly in `shm->stats` and is rendered through
descriptor tables, while hot/security-relevant counters route through per-child
SPSC rings into a parent-private aggregate. The shutdown text report is now a
thin orchestrator plus section files under `stats/dump/`, `stats/childop/`,
`stats/network/`, and `stats/kcov/`; JSON and periodic reporting remain their
own entry points.
