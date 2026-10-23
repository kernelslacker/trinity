# stats/ - Telemetry, Aggregation, and Reporting Subsystem

Central counter collection, aggregation, and dump layer for Trinity. Most
subsystems (kcov, cmp_hints, childops, random_syscall, corruption defenses)
bump counters here; this directory turns those counters into text, JSON, JSONL
timeseries, and periodic operator-facing dumps.

## Layout (74 .c files + 53 headers, ~22,660 LOC)

16 of those `.c` files and 48 of the headers are the per-subsystem counter
tree under `stats/subsys/` (~391 + ~4,749 LOC), listed as one row at the
bottom rather than enumerated. The renderers below are the other 58.

| Path | Role |
|---|---|
| stats.c | Shutdown report orchestrator. `dump_stats()` owns section order only. |
| common.c | Shared helpers: text-PC check, op names, row printer, top-N insert. |
| category.c | `stat_category` value loads and shared text-category renderer. |
| categories/base.c | Core/blob/oracle/staged descriptor tables. |
| categories/network.c | Network childop descriptor tables. |
| dump.c | Empty compatibility TU; text dump leaves live in subdirectories. |
| dump/syscall.c | Runtime header, syscall category histogram, per-syscall summary tables, wedge top-Ns. |
| dump/fd.c | FD lifecycle/provider summaries. |
| dump/shared-buffer.c | Shared-buffer misc and range-overlap offender summary. |
| dump/oracle.c | Oracle anomaly counters. |
| dump/subsystems.c | Fuzzer subsystem counters: VFS writes, genl and nfnl families, netlink generator, rtnl ack oracle, bpf fd provider, eBPF generator, zombie slots. |
| dump/corruption.c | Corruption, deferred-free, pool, and paired-fd diagnostics. |
| dump/strategy.c | Strategy, plateau, picker, and per-syscall CMP-insert summaries. |
| dump/corpus-tail.c | Minicorpus, cmp_hints, taint, and late tail summaries. |
| childop/local.c | Local childop run rows, decay recency, fd-delta, and topology-pair shadow dumps. |
| childop/ranked.c | Ranked childop tables: wall time, edges, util, skips, wedges. |
| network/childops.c | Network childop aggregate sections. |
| kcov/dump.c | Shutdown KCOV coverage and comparison diagnostics block — now only the renderer ordering; the blocks live in the `kcov/dump-*.c` siblings. |
| kcov/dump-base.c | Base KCOV counters, warm known-hits, exit-edge delta and totals. |
| kcov/dump-topn.c | Top-edges / cold-syscall, per-syscall yield and dedup top-Ns. |
| kcov/dump-remote.c | Remote edge producers plus per-syscall last-edge / last-EFAULT / local-PC top-Ns. |
| kcov/dump-reexec.c | CMP hint tier, reexec, and ring replay blocks. |
| kcov/dump-shadow.c | Shadow measurements, KCOV probe costs, KCOV dispatch stats. |
| kcov/dump-internal.h | Private renderer prototypes shared across `stats/kcov/dump-*.c`. |
| kcov/cmp/periodic.c | Public entry `kcov_cmp_stats_periodic_dump()`: previous-window state, elapsed gate, delta computation, render-block fan-out; plus the static renderers for the RedQueen burst-drain cohort and the per-callsite splits that no sibling owns. |
| kcov/cmp/base.c | Shared `kcov_cmp_rate_line()` emitter; scalar CMP-rich per-syscall top-N table; wild-write rate rows. |
| kcov/cmp/redqueen.c | RedQueen reexec per-syscall top-N, per-slot histograms, and reexec skip-reason breakdown. |
| kcov/cmp/pool.c | Raw cmp-hint pool + tier: oldpool per-syscall top-N, oldpool-vs-shadow, PC-win conversion split, per-entry feedback scoring, recent-CMP-pool tier. |
| kcov/cmp/hyp_saturation.c | Typed hypothesis pool-grid lane: per-syscall saturation top-N with per-kind fill, plus the per-entry outcome aggregates that have no `kcov_shm` scalar twin. |
| kcov/cmp/hyp_shadow.c | Typed hypothesis SHADOW umbrella: flat lifecycle counters plus the per-kind / consume / picker / state-transition / outcome-partition breakouts. |
| kcov/cmp/hyp_live_inject.c | Typed hypothesis LIVE inject lane: the (gate_passed, injected, no_pick) triad and its per-kind partition, per-reason gate-close breakdown, and the BOUNDARY scorecard. |
| kcov/cmp/hyp_would.c | Typed hypothesis pure-observation lane: would-pick, would-promote, would-demote. |
| kcov/cmp/hyp_hist.c | Typed hypothesis histograms: the 8-band score-bucket census and the per-probe-class emission census. |
| kcov/cmp/childop.c | Childop CMP consume shadow block (childop-specific index bounds). |
| kcov/cmp/cohort.c | Cross-subsystem A/B and sidecar rows: baseline inject denom, handle_arg_op prop_ring, frontier cold-weight blend, adaptive remote-KCOV, per-arg ownership sidecar, structure-aware picker cohort. |
| kcov/cmp/diag.c | Steady periodic diagnostics: KCOV mode mix, KCOV CMP DIAG errnos, KCOV PC DIAG errnos + retry counters. |
| kcov/cmp/internal.h | Private renderer prototypes shared across `stats/kcov/cmp/` TUs. |
| kcov/cmp/hyp_kind_labels.h | The one `enum cmp_hypothesis_kind` label table the per-kind renderers print from, with a compile-time one-label-per-kind check. |
| json/dump.c | `--stats-json` top-level orchestrator: root object, `"stats"` wrapper, and section order. |
| json/common.c | JSON mechanics: string escape and `stat_category_emit_json()` descriptor renderer. |
| json/syscalls.c | Per-syscall JSON array. |
| json/kcov.c | KCOV JSON block (counters, transition globals, top-Ns, cold syscalls, previous-window snapshots). |
| json/minicorpus.c | Minicorpus JSON block (mutators, stack-depth, saves/evicts, replay-wins, sequence chains). |
| json/cmp-hints.c | cmp_hints JSON summary (total hints, syscalls-with-hints). |
| json/core.c | Non-network JSON section emitters + basic-subsystem descriptor tables. |
| json/network.c | Network / iouring-network long-chain JSON section emitters. |
| json/tail.c | `vsock_transport_churn` JSON tail. |
| json/type_graph.c | JSON shape for the resource type-graph observer (the observer itself is `objects/type-graph.c`); kept under `stats/json/` so the schema check finds its format literals. |
| json/internal.h | Private cross-file interface for the `stats/json/` cluster; only `dump_stats_json()` is exported, from `include/stats-internal.h`. |
| periodic/strategy-topn.c | Shadow strategy per-syscall top-N helpers called at shutdown from `dump/strategy.c`. |
| periodic/counter-rates.c | `periodic_counter_rates[]` rate table + `periodic_counter_rates_dump()` parent-tick emitter. |
| periodic/childop-split.c | Childop-vs-random-syscall walltime/syscalls/iterations split emitter. |
| periodic/cost-pool.c | Cost-pool active-count + shadow/live selector-fraction snapshot. |
| periodic/top-syscalls.c | Per-syscall bandit/explorer/frontier/RQ/warm-reserve top-N deltas. |
| periodic/vma.c | Parent + child `/proc/*/maps` line-count snapshot for VMA-leak triage. |
| log.c | `--stats-log-file` and the `--stats` JSONL timeseries (`stats-timeseries-*.jsonl`) file lifecycle. |
| runid.c | Run identity, boot/cache provenance, and shutdown delta manifest. |
| corrupt_ptr.c | Corrupt-pointer attribution and deferred-free reject reporting. |
| stats-ring.c | Per-child SPSC ring drain into parent-private aggregates. |
| kcov_diag.c | Descriptor-driven KCOV per-syscall diagnostic helpers. |
| rotation_event.c | Observation-only durable JSONL event stream, one record per closed strategy-rotation window, written by the CAS-winning child through `lib/jsonl.c`. Each child parks its copy of the sink fd above `PROTECTED_FD_HIGH_BASE` (the parent keeps its low number) and the protected-fd registry names it. No parent-side aggregate. |
| arm-verdict.h | Dead-arm verdict status tokens (`enum arm_verdict`, `arm_verdict_to_str()`). `stats/dump/subsystems.c` and `stats/json/tail.c` include it, but no emitter reports a verdict any more. |
| subsys/*.h, subsys/*.c | Per-subsystem counter tree: each `<subsys>.h` declares that subsystem's counter struct (pulled into `shm->stats` via `include/stats.h`) and the matching `<subsys>.c` declares its `stat_category` descriptor table with `STAT_FIELD_SUB()`. 48 headers, 16 descriptor TUs — headers without a table are subsystems whose counters are rendered from elsewhere. |

## Data Model

Two parallel counter stores, by design:

1. **`shm->stats`** (kernel-visible shared memory, `include/stats.h`) - the
   original counter store. Hundreds of childop-specific counters are declared
   once via `STAT_FIELD()`/`STAT_FIELD_SUB()` and grouped into `stat_category`
   tables — one per subsystem under `stats/subsys/`, with the leftover
   cross-prefix and staged tables under `stats/categories/`. Each
   `stats/subsys/<subsys>.h` also declares that subsystem's counter struct,
   and `include/stats.h` pulls all 48 of them in. Childops still increment
   most of these directly; a wild
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
   declaring the struct member in the subsystem's `stats/subsys/<subsys>.h`
   and appending one `STAT_FIELD_SUB()` row to the matching
   `stats/subsys/<subsys>.c` (or, for the cross-prefix and staged tables,
   `stats/categories/`). Text and JSON renderers both walk the descriptors,
   so they cannot drift from the struct layout.
2. **SPSC ring for hardened counters** - hot/security-relevant fields move
   through `stats_ring_enqueue()` into `parent_stats`. A contributor adding a
   new security-relevant counter should choose this path rather than direct
   `shm->stats` writes.
3. **Section-oriented text dump** - `dump_stats()` in `stats.c` lists the fixed
   shutdown report order. Leaf renderers live under `stats/dump/`,
   `stats/childop/`, `stats/network/`, and `stats/kcov/`, so a new section has
   a natural smaller home.
4. **Stateful periodic logic stays separate** - `stats/kcov/cmp/periodic.c`
   keeps the elapsed-time gate and previous-window snapshots for
   cmp_hints/redqueen diagnostics; the fan-out render helpers live in the
   per-domain siblings under `stats/kcov/cmp/`.  This subtree is intentionally
   not a pure shutdown-render tree.
5. **Ring pointer hardening in `stats_ring_drain_all()`** - the drainer reads
   each child's ring through `expected_stats_rings[]`, a parent-private (heap)
   copy of the ring addresses taken before fork, and only compares the
   child-writable `child->stats_ring` against it to count and report an
   overwrite.

## Integration Points

- `main/loop.c` `run_periodic_surfaces()` calls the rate-limited periodic
  surfaces: corrupt-pointer spike check, defense counters, cost pool, top
  syscalls, VMA count, and cmp_hints periodic diagnostics.
- `main/trinity.c` calls `dump_stats()` once at shutdown; this is the sole entry
  point for the full text/JSON report.
- `stats/stats-ring.c` `stats_ring_drain_all()` drains each live child's SPSC
  ring into `parent_stats` once per parent main-loop iteration.
- `kcov/` feeds KCOV counters rendered by `stats/kcov/dump.c` and JSON KCOV
  sections in `stats/json/kcov.c`; `kcov/lifecycle.c` also enqueues ring deltas.
- `cmp_hints/` feeds the periodic front-end in `stats/kcov/cmp/`; top
  per-syscall CMP insert rows in the shutdown report are rendered from
  `stats/dump/strategy.c` and `stats/kcov/dump.c`.
- `strategy/strategy-stats-dump.c` provides a separate operator summary called
  from `dump_stats()` alongside the stats-owned sections.
- `child-altop-score.c` owns `childop_score_dump()` and
  `childop_outcome_window_dump()`; `dump_stats()` invokes them as part of the
  childop block.
- `include/stats.h`, `include/stats-internal.h`, and `include/stats_ring.h` are
  the three headers this directory is built around: shared-memory counter
  layout, private cross-file stats interfaces, and ring slot definitions.

## Areas of Attention

1. **`stats/kcov/cmp/periodic.c` still owns the time-gated periodic dump
   orchestrator** - previous-window snapshots and any-delta gates live here.
   The render blocks are per-domain siblings (the burst-drain and callsite
   blocks no sibling owns are static helpers in this file), but the
   top-level function is still ~800 lines and the widest hunk in the
   subtree.  What is left is window-state plumbing, not rendering: the
   `prev_*` statics, the `cur_*` loads, the first-window arm, the `delta_*`
   computation, the any-delta gate and the commit all read or write the same
   ~220 `cur_`/`delta_`/`prev_` variables, so none of them can be carved out
   by moving code alone; shrinking them means gathering the window state
   into a struct.  Any new top-level periodic counter has to add its
   declaration, load, arm, delta, render, and commit here.
2. **The shutdown KCOV block is now a five-way render family** -
   `stats/kcov/dump.c` keeps only the ordering; base, top-N, remote, reexec
   and shadow blocks live in `stats/kcov/dump-<domain>.c` behind
   `dump-internal.h`. Output is byte-for-byte identical to the pre-split
   single-file layout, so a new KCOV block goes in the matching domain file
   plus one prototype and one ordered call.
3. **JSON descriptor ownership is still mixed** - `stats/json/` now mirrors
   the text-dump layout (common, syscalls, kcov, minicorpus, cmp-hints,
   core, network, tail, type_graph, dump), but `stats/json/core.c` still owns
   JSON-local descriptor tables that would more naturally live under
   `stats/subsys/` or `stats/categories/` (`network.c` and `tail.c` only
   compose categories defined elsewhere).  Follow-up
   work should migrate one domain at a time, keeping schema order unchanged.
4. **Counter-store choice is still manual** - direct `shm->stats` fields remain
   writable by a wild kernel store; only the ring-fed `parent_stats` aggregate is
   hardened. Review new counters for whether they are telemetry or authoritative
   control/diagnostic state.
5. **Ring pointer hardening is load-bearing** - `expected_stats_rings[]` covers
   an observed recycled child-slot failure mode (a late write leaving a wild
   `child->stats_ring`), not a theoretical cleanup.  It is only trustworthy
   while it stays in parent-private memory; do not move it into a shared pool.

## Summary

Counters are produced across the codebase and converge here through two paths:
bulk childop telemetry lands directly in `shm->stats` and is rendered through
descriptor tables, while hot/security-relevant counters route through per-child
SPSC rings into a parent-private aggregate. The shutdown text report is now a
thin orchestrator plus section files under `stats/dump/`, `stats/childop/`,
`stats/network/`, and `stats/kcov/`; JSON and periodic reporting remain their
own entry points.
