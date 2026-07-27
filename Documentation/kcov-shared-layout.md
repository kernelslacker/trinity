# kcov-shared layout notes

Companion to `include/kcov-shared.h`.  The header keeps per-field
member docs in each `include/kcov-groups/<group>.h`, one-line member
tags at the aggregation point, and the load-bearing partition
invariants inline; this document collects the cross-cutting design
rationale those inline pointers refer to.  Sections are anchored by
member name and ordered to match declaration order in the header.

## pc_ctx

Per-syscall split of `kcov_collect()` activity by collection mode.
A remote-sampled syscall lands in a DIFFERENT mode -- the kernel puts
the task in `KCOV_MODE_REMOTE` and drops synchronous local PC -- so a
static remote-sampling policy can spend half a syscall's samples on a
mode with no annotated producer, invisible today behind the single
global `remote_calls` counter.

- `local_pc_calls[nr]` / `remote_pc_calls[nr]` count every
  `kcov_collect()` invocation in that mode (apples-to-apples against
  `per_syscall.per_syscall_calls[]` which still tracks both modes
  summed).
- `local_pc_edge_calls[nr]` / `remote_pc_edge_calls[nr]` count calls
  that produced `>= 1` fresh edge (call-count semantics matching
  `per_syscall.per_syscall_edges[]`).
- `local_pc_edge_count[nr]` / `remote_pc_edge_count[nr]` carry the raw
  fresh-edge tally so a single big call is not flattened to the same
  weight as a tiny one.

All bumped in `kcov_collect()` keyed on `kc->remote_mode`.  The
`childop_*_pc_*[]` mirrors are indexed by `op = nr -
CHILDOP_KCOV_NR_BASE` inside `kcov_collect()` with the same semantics.

## remote_enable

The `pc_ctx` split above attributes calls by the mode the kernel
ultimately produced coverage in, which folds "remote was attempted and
the kernel refused" into the local-mode column -- a HEAVY-flagged
syscall whose `KCOV_REMOTE_ENABLE` consistently returns `EBADF` reads
as "zero remote yield" through the yield-side counters,
indistinguishable from "remote was sampled and the kernel actually ran
the work on the calling task".

The four counters partition the enable path itself so a genuinely
zero-yield remote syscall (kernel ran remote, found nothing) can be
told apart from one where remote was never actually enabled:

- `remote_enable_requested` -- entered `kcov_enable_remote()` and
  about to attempt the ioctl.
- `remote_enable_succeeded` -- the ioctl returned 0; the call
  genuinely sampled remote coverage.
- `remote_enable_failed` -- the ioctl exhausted its `EINTR` retries or
  returned a non-`EINTR` error and flipped `remote_capable=false`.
- `remote_fallback_to_local` -- after a failed remote enable, the
  PC-mode fallback ioctl in turn succeeded, so the child finished the
  syscall in local mode.

All bumped inside `kcov_enable_remote()` keyed on the nr it now takes
as a parameter; childop callers (`nr >= CHILDOP_KCOV_NR_BASE`) bypass
the bumps via the standard `nr < MAX_NR_SYSCALL` gate.

## plateau

Sliding-window edge-rate plateau detector state.  Sampled at the 600s
parent stats tick: each tick, `delta = edges_found - plateau_prev_edges`
is the count of new edges discovered in the most recent
`KCOV_PLATEAU_WINDOW_SEC` window.  When the delta drops below
`KCOV_PLATEAU_ENTER_THRESHOLD` (rate < 1 edge per 60s sustained over
the 10-minute window) the parent enters PLATEAU state and emits a
one-line warning to `stats.log`; a matching CLEARED line fires when
the rate climbs back above threshold.

Entry into PLATEAU also fires `strategy_plateau_response()`, which
forces an immediate strategy rotation into the plateau-intervention
layer.  That layer is a flat round-robin among RRC-biased replay,
anti-prior accept gating, and uniform random; the rotation does not
pin a mode based on the hypothesis classifier.

The published hypothesis is consumed separately at per-call gates in
`child/child.c` (`CHILDOP_DOMINANT` raises the alt-op burst threshold)
and in `minicorpus.c` (`CMP_RISING_PC_FLAT` doubles the replay rate
and narrows the slot picker) -- see the strategy header for the full
consumer contract.  Interventions unwind automatically on the matching
CLEARED edge.

## reexec_flat

Greedy CMP RedQueen re-exec funnel.  Every counter is bumped once per
re-exec dispatch (or once per gated skip) so the funnel

    attribution_found -> attempts -> new_cmps_total
                                  -> skipped_destructive
                                  -> skipped_validate_silent
                                  -> window_cap_hit

is directly observable.  `attribution_ambiguous` is bumped once per
`(cmp_ip, value)` where more than one arg slot matched, before
first-match-wins picked one.

`reexec_attribution_width_match` is the width-aware fallback tally:
counted SEPARATELY from `reexec_attribution_found` so the exact
full-width predicate's low-noise numerator stays clean.  Bumped from
`cmp_hints_collect()` when the exact-pass `arg` vs `arg2` compare
misses, the comparison size is narrower than a long, and a
width-masked rescan finds EXACTLY one matching slot (any masked
ambiguity is dropped rather than guessed -- the masked predicate's
higher hit rate makes first-match-wins unreliable here).  Total
successful attributions ingested into `reexec_pending[]` is therefore
(`reexec_attribution_found + reexec_attribution_width_match`).

## transitions

Shadow transition-coverage map and counters.  All four counters and
the map stay at zero when the mode is OFF; the map and per-syscall
arrays are still allocated (size is fixed at compile time and the byte
cost is fleet-acceptable, ~16 MB).

- `transition_seen[]` -- one byte per (prev_canon_pc, cur_canon_pc)
  hash slot.  Bit 0 is the seen flag bumped from `kcov_collect()`; the
  upper seven bits are reserved for a future bucket layer that would
  parallel `bucket_seen[]`'s 8-bucket hit-count semantics.
- `transition_edges_found` -- count of slot bits ever flipped 0 -> 1.
  Today this tracks distinct slot occupancy; the name keeps the
  PC-side `edges_found` / `distinct_edges` naming pattern so a future
  bucket layer can split the two cleanly.
- `transition_distinct_edges` -- distinct first-sighting count of new
  transition slots.  Identical to `transition_edges_found` until a
  bucket layer is added.
- `per_syscall_transition_edges[nr]` -- call-count semantics: bumped
  once per `kcov_collect()` call that flipped at least one new
  transition slot.  Mirrors `per_syscall.per_syscall_edges[]`.
- `per_syscall_transition_edges_previous[nr]` -- snapshot at the
  previous `dump_stats()` interval; drives the "top syscalls by recent
  transition growth" delta block.
- `per_syscall_transition_edges_real[nr]` -- real edge-flip count:
  sum across all calls of the number of new transition slots flipped
  in that call.  A single call that opens an entirely new
  control-flow region bumps this by the size of the region.
- `per_syscall_transition_edges_real_local[nr]` -- local-mode-only
  mirror.  Bumped only when the collecting kcov child is NOT in remote
  mode AND `kcov_transition_reward_mode != OFF`.  Consumed by the
  `frontier_cold_weight()` blend as the transition-yield term so the
  live picker (under COMBINED) sees a transition signal restricted to
  traces whose PC ordering Trinity can trust.

## reexec_gate

Measurement-correctness counters for the RedQueen attribution +
re-exec funnel.  The pre-existing `reexec_*` family covers the flat
aggregates and per-syscall partitions of attempts + ambiguity; the
per-call gate disposition (why a parent call with staged attributions
did or did not fire a re-exec) was a single un-partitioned gap between
`reexec_attribution_found` and `reexec_attempts`, and the per-childop
dimension of the same funnel was invisible.

The split mirrors the existing `reexec_*_by_syscall` pattern for the
per-syscall head of the funnel and adds the matching per-childop
arrays.  Snapshot health is the consumer-side counterpart of
`dispatch_args_valid`: a non-zero `cmp_attribution_snapshot_unavailable`
means the `[11-snapshot]` `dispatch_args[]` feed is not reaching
attribution.

Per-call gate disposition at `dispatch_step`'s re-exec tail is
**mutually exclusive**: each `dispatch_step` that reaches the tail
bumps EXACTLY ONE of the eight counters (first gate to fail in
evaluation order, or `_pass` when all gates cleared and
`redqueen_reexec_step` ran).  Sum across the eight == total
`dispatch_step` calls that reached the tail, which is the parent-call
population the gate samples from.  Skip-reasons in evaluation order:

- `in_reexec` -- recursion guard (the inner `dispatch_step` the
  re-exec helper itself invoked).
- `disabled` -- child not in the A/B redqueen-enabled cohort.
- `mode` -- PC-mode child; CMP-mode is required to produce attribution.
- `chain_mid` -- `in_chain_mid_step` set; a chain replay's saved step
  sequence cannot accommodate an intermediate re-exec.
- `no_new_cmp` -- parent call produced no bloom-novel CMP records.
- `no_pending` -- attribution scan staged zero matches.
- `rate` -- rate gate (`ONE_IN(N)`) did not fire and plateau-burst
  was not active.
- `pass` -- all gates cleared, `redqueen_reexec_step` ran.

The gap `reexec_attribution_found - reexec_attempts` is now bucketed
by this counter family rather than inferred from a single global delta.

`cmp_attribution_calls_eligible` is the denominator for the
per-eligible-call attribution win rate (child != NULL,
`redqueen_enabled`, `!in_reexec`, `reexec_pending_count <
MAX_REEXEC_PENDING`, entry != NULL, `entry->num_args > 0`,
`dispatch_args_valid`).  `cmp_attribution_snapshot_unavailable` bumps
when the cohort gate cleared and `entry->num_args > 0`, but
`rec->dispatch_args_valid` was false -- a healthy run holds this at
zero.

## reexec_arms

RedQueen plateau_burst per-call drain-cap A/B measure arm counters.

The go/no-go metric for the `burst_drain_arm_b` measure lives in the
**distinct-edge lift domain**, not the CMP-record domain: the 85k
distinct-PC-edge wall is what the plateau intensification is meant to
break, but `reexec_new_cmps_total` counts bloom-novel CMP records and
a fresh CMP that opens no new distinct edge is invisible to that
wall.  `reexec_new_edges_total` wires the 6th `dispatch_step()`
out-param (`pcres.transition_edges_real_local` at
`random_syscall/dispatch.c:709`) into `redqueen_reexec_step()`'s
`inner_new_cmp > 0` success block and accumulates it in lock-step
with `reexec_new_cmps_total`, so a run can be scored on
transition-distinct-edge lift instead of CMP-record lift.

The `_by_arm[2]` triplet partitions each numerator by the child's
`burst_drain_arm_b` stamp (arm A = index 0, arm B = index 1), bumped
from `redqueen_reexec_step()` inside the same critical sections that
bump the flat counters.  `reexec_attempts_by_arm` supplies the
per-arm denominator; a per-arm distinct-edge ratio is then

    reexec_new_edges_by_arm[B] / reexec_attempts_by_arm[B]

versus the same ratio for arm A -- the shadow success criterion is
arm-B >= arm-A.

## --kcov-trace-size

Per-child KCOV PC-trace buffer size, in unsigned longs.  Must be a
power of 2 in `[KCOV_TRACE_SIZE, KCOV_TRACE_SIZE_MAX]`
(default `KCOV_TRACE_SIZE = 262144 longs = 2 MB` on 64-bit; maximum
`4M longs = 32 MB`).

A/B knob for testing whether the hot syscalls
(`mincore` / `mlock` / `writev` / `shmget` / `shmat`) that today
saturate `trace_buf[0]` at `KCOV_TRACE_SIZE-1` are dropping real tail
edges.  Default value is byte-identical to a build without this
flag.

## --frontier-noise-sample

Shadow-only per-syscall clean-vs-noisy attribution sampler.  With
`N > 0`, every Nth per-syscall enable/disable bracket in
`dispatch/syscall-exec.c` snapshots the shared `edges_found` counter
before enable and after disable, records the delta into
`kcov_shm->per_syscall.per_syscall_edges_noisy[nr]`, and bumps
`per_syscall_noisy_samples[nr]` so a reader can scale the sampled
sum back up by N to estimate the full-population global-delta
denominator.

Paired with the pre-existing `per_syscall_edges[]` clean numerator
and the `per_syscall_edges_clean_remote[]` remote-context split
(bumped inside `kcov_collect`'s `found_new` branch when
`kc->remote_mode`), this feeds the per-syscall attribution-confidence
diagnostic block in the stats dump.

SHADOW-ONLY: no live picker, accept-gate, or scoring code reads any
of the three counters -- selection stays byte-identical to a build
with `N=0`.  With `N=0` the sampler helpers short-circuit at the
earliest gate and issue zero `edges_found` loads on the syscall hot
path, so the default build carries zero added cost.

Suggested first fleet value: `64` (loads `~1.5%` of the time,
statistically usable denominator over a run since each syscall fires
thousands of times).  Cadence is a single non-atomic per-child
increment on file-scope state in `dispatch/syscall-exec.c`; no
cross-child shared counter is touched for the cadence itself.
Default 0 (off).

## --kcov-transition-coverage

Shadow transition-coverage map mode.  Hashes consecutive canonical
PCs into a separate 16M-slot map and surfaces a transition top-N
beside the PC top-N in the stats dump.

- `shadow` (default): compute the transition hash; no effect on
  reward / frontier / plateau steering.
- `off`: skip the per-PC transition hash entirely.

## --kcov-transition-reward

Transition-edge reward mode (requires
`--kcov-transition-coverage=shadow`).

- `combined` (default): feed the capped transition delta into
  `frontier_cold_weight`, `bandit_record_pull`, and the frontier-edge
  ring so syscalls producing only transitions earn frontier credit.
- `shadow-only`: compute the transition reward and bump per-strategy
  attribution counters in `shm->stats` but leave live picker
  behaviour byte-identical to the pre-knob baseline -- rollback
  path.
- `off`: skip the reward path entirely.

Remote-mode transitions are excluded from live reward under
`combined` until ordering quality is checked.
