# childop-canary-queue

The dormant-childop canary promotion queue flips the runtime gate
(`dormant_op_disabled[]`) for one dormant op at a time, runs that op on
a reserved canary child for a fixed iteration budget, and promotes the
op into the random alt-op picker when it produces new edges without
self-crashing.  Failed canaries are demoted with a backoff.  The slots
are carved from the front of the existing `--alt-op-children` pool.

No childop implementation is modified by this queue.  A broken op is
detected via the demote path; the cure is to leave it dormant.

## COW seeding vs shm residency

State lives entirely in parent-private static memory.  The gate vector
(`dormant_op_disabled[]`) and the dense `enabled_altops[]` vector
rebuilt from it are seeded into children by `fork()` COW, so the
INITIAL snapshot is shared, but they are not shm-resident: any runtime
flip from `dormant_op_set()` is parent-only.

## Propagation model

State changes here are seen by NEW children (next respawn forward).
Already-running random children -- those at slot index
>= `alt_op_children`, where `pick_op_type()` may select an alt-op with
~5% probability -- continue with their fork-time snapshot of
`dormant_op_disabled[]` / `enabled_altops[]` until they exit.  Slot
turnover (the natural respawn cadence) propagates the new state
organically across the fleet.  Dedicated canary slots (the first
`canary_slots` indices) re-stamp their op_type on every respawn via
`assign_dedicated_alt_op()` and so always see the current queue state.

## Why runtime flips are not published

Runtime promotions/demotions are deliberately not published into the
shared region: already-forked random children would need an
shm-resident gate (plus persistence) to observe them, and that cost is
not paid here.

## Priority seed list

Consumed in this order before the FIFO walk over remaining dormant ops:

1. `genetlink_fuzzer`
2. `bpf_lifecycle`
3. `iouring_recipes`
4. `nftables_churn`
5. `perf_chains`
6. `tracefs_fuzzer`
7. `tls_rotate`
8. `af_unix_scm_rights_gc_churn`
9. `userns_fuzzer`
10. `sock_diag_walker`

## --alt-op-children

Reserve `N` children to run dedicated alt ops
(`mmap_lifecycle`, `mprotect_split`, ...) round-robin instead of
mixing them at 1% in every child.  Alt ops that need a stable per-op
address space (mmap/mprotect churn) get concentrated dispatch on
their reserved children; the rest of the fleet stays free to focus
on the random syscall picker.

Default: `max(2, --children/8)`.

## --canary-seed

Override the built-in priority seed list.  Accepts a comma-separated
list of childop names; names match `alt_op_name`
(e.g. `genetlink_fuzzer,bpf_lifecycle`).  Unknown names abort
startup.  Use this when a targeted run needs a specific dormant op
promoted first.

## --canary-slots

Reserve `N` slots from the front of `--alt-op-children` to run the
dormant-op canary queue.  Default: `min(alt-op-children, 2)` when
unset.  Clamped to `min(N, alt_op_children)`; `N=0` disables the
queue identically to `--no-canary-queue`.

## --canary-window

Invocations of the active canary op per window.  Counted against the
per-op invocation counter, not the fleet-wide op count, so window
size is independent of `-C` and `--canary-slots`.  Lower windows are
too noisy to promote on; higher windows let a useless op squat a
slot for too long.  Default 10000, range 1000..1000000.

## --no-canary-queue

Disable the dormant-childop canary queue entirely.  The dormant gate
is consulted as a static compile-time vector and no canary slots are
reserved.  Use this to revert the canary machinery off completely
for A/B comparisons against a build without the queue.

## --childop-kcov-attribution

Per-childop KCOV attribution mode.  Controls whether alt-op edges
are attributed to the per-childop `edges_clean` counter (the signal
`adapt_budget` and the canary queue consume) or only to the
diagnostic `edges_discovered` global-delta comparator.

- `off`: no bracketing; `childop_edges_clean` stays zero.  Budget
  multipliers stay at unity and canary windows always demote on
  `zero_edges`.
- `dual` (default): bracket every eligible alt-op and publish the
  per-call edge delta to `childop_edges_clean` -- `adapt_budget` and
  the canary queue consume this clean signal; the global-delta path
  keeps writing `childop_edges_discovered` as a diagnostic
  comparator.
- `on`: reserved; identical to `dual` until the discovered counter
  is retired.

## --fork-pressure-drain

Under sustained `fork()` failure (`>=100` consecutive
`spawn_child` failures), suppress canary picks of pid-heavy ops
(`pidfd_storm`, `qrtr_bind_race`, `pfkey_spd_walk`,
`l2tp_ifname_race`, `statmount_idmap_overflow`, `sysfs_string_race`)
for 30 s so the canary picker stops piling new fork demand on a
parent already losing the spawn race.

`fork_storm` is always skipped via the risky-defer set (independent
of this flag).  Default off; opt-in only.
