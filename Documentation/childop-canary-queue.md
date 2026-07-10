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
