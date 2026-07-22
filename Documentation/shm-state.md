# shm state design notes

Companion to `include/shm.h`.  The header keeps per-field member docs,
one-line memory-model notes, and load-bearing degrade-safe invariants
inline; this document collects the multi-paragraph design rationale
those inline pointers refer to.  Sections are ordered roughly to match
declaration order in the header.

## Parent-provisioned startup-isolation latches

Set in `setup_startup_isolation()` (called once from `init_pre_fork()`
after `do_uid0_check()`, root-gated, in the parent's brief root window
before any fork), zeroed by `create_shm()`'s memset.  Children read
these in `init_child_setup_sandbox` to decide whether to do the
per-child net/mount unshare or inherit the parent's provisioned ns.

Two independent halves, one per namespace kind:

- `net_ready` latches true iff the parent successfully entered a private
  netns (`unshare(CLONE_NEWNET)` succeeded as part of the combined
  `CLONE_NEWNET|CLONE_NEWNS` unshare).  Children skip their per-child
  `unshare(CLONE_NEWNET)` -- they already inherit the (empty-but-ours)
  netns via fork().

- `mnt_ready` latches true iff the parent's `unshare(CLONE_NEWNS)` AND
  the subsequent `MS_REC|MS_PRIVATE` remount of `/` both succeeded.
  Children skip the per-child unshare + private-remount dance entirely.
  The bar is "containment guaranteed" -- if the private remount failed
  the latch stays false even though the unshare itself succeeded, so
  children fall back to their existing per-child path and the
  `no_private_ns` latch keeps log spam bounded.

Either latch false means "degrade to today's per-child unshare path".
Non-root, `--no-startup-isolation`, EPERM or ENOSYS on any step all
land in the degraded state with zero behaviour change vs. a
pre-isolation trinity build; logged once by the parent.  Per-child
IPC/IO/PID unshares stay exactly where they are (cheap, per-child, no
parent provisioning required).

### Independent latching

The net and mount halves latch independently: a successful
`unshare(CLONE_NEWNET)` plus lo provisioning sets `net_ready` even if
the `MS_PRIVATE` remount on the mount side failed, and vice versa.
Children consult each latch on its own and fall back to the per-child
unshare path for whichever half degraded.

### Memory ordering

RELAXED atomic accesses match the `no_private_ns` / `no_pidns` latch
convention -- the writes happen before `fork_children()`, and the
`fork()` itself supplies the cross-process happens-before edge to every
child reader.

### Why `netns_fd` lives here

`netns_fd` is a dup'd `/proc/self/ns/net` handle to the provisioned
netns, opened by `setup_startup_isolation()` once `net_ready` latches.
Stashed here so childops driving the BPF link API attach types whose
`target_fd` is a netns handle (`sk_lookup`, `flow_dissector`,
`sk_reuseport`) can pull a ready-made fd instead of re-opening
`/proc/self/ns/net` per call.  Sentinel `-1` means "not published" --
either `net_ready` is false (so reading this field is meaningless
anyway) or `net_ready` latched but the open failed (best-effort: net
provisioning is still done, only the BPF-link freebie is absent).
Initialised to `-1` by `create_shm()` over the top of the memset-zero
so the sentinel is honest even before the parent has run its setup
pass.

## Per-arm syscall-level exposure counters

The existing per-arm series (`bandit_pulls[]`,
`pc_edge_calls_by_strategy[]`, `bandit_reward_calls[]`) all measure
WINDOWS or NEW-EDGE CALLS -- the bandit reward signal -- and leave the
denominator side implicit.  Without an explicit per-arm dispatch count
the only way to derive "how many syscalls actually ran under this arm
this run" is to scale `stats.reward_per_fleet_op_window` by the window
mix, which mixes in syscall latency, explorer/alt-op share, blocking
behaviour, and rotation drift.  That makes tuning A/B comparisons
across runs hard: a reward delta might mean the arm is genuinely
better, or just that this run's background changed enough to shift
exposure.

The exposure counters are the denominators those analyses need:

- `strategy_picks[]` -- every syscall pick credited to an arm, bumped
  in `set_syscall_nr()` right after the arm is resolved for this pick.
  Explorer-pool children always run `STRATEGY_RANDOM` and bump
  `strategy_picks[STRATEGY_RANDOM]` directly; the bandit pool bumps
  the arm `shm->current_strategy` resolved to.  This is the widest
  population -- all dispatched syscalls.

- `strategy_bandit_pool_ops[]` -- strict subset of `strategy_picks`,
  bumped only on the bandit-pool path.  Lets the operator compute
  `(strategy_picks[a] - strategy_bandit_pool_ops[a])` as the
  explorer-pool contribution per arm (zero for non-RANDOM arms,
  monotonic with `explorer_children` for `STRATEGY_RANDOM`).  This is
  the population that pairs cleanly with `pc_edge_calls_by_strategy[]`
  -- both are bandit-pool only and exclude explorer contributions.

- `strategy_completed_calls[]` -- bumped at the end of `dispatch_step`
  after the syscall has returned and post-call bookkeeping has run.
  Excludes `set_syscall_nr()` FAIL returns (no syscall was dispatched),
  so the ratio `strategy_completed_calls[a] / strategy_picks[a]` is
  the per-arm dispatch success rate -- a low ratio surfaces an arm
  whose picker policy is repeatedly hitting unsatisfiable eligibility
  / validation gates.

### Memory ordering and contention

Multi-producer (every child writes); RELAXED `fetch_add` on the write
side, RELAXED loads in `dump_strategy_stats()` at end of run.  Per-arm
cacheline contention is acceptable because these are diagnostic
counters consulted at run-end and by future intervention classifiers
(plateau reads these alongside `pc_edge_calls_by_strategy` to decide
which arm to force during a plateau intervention) -- not on the hot
pick path.

## Plateau intervention mode rotation state

When the kcov plateau detector has the fleet in an intervention window
(`SR_PLATEAU_FORCE`), the orchestrator round-robins among
`PIM_UNIFORM_RANDOM` / `PIM_ANTI_PRIOR` / `PIM_RRC_BIASED` /
`PIM_COVERAGE_FRONTIER` at each rotation so the four rescue shapes get
equal exposure and per-mode A/B comparison stays defensible.

### Rotation dispatch

`plateau_intervention_mode_current` is the latched mode for the
current intervention window, published by `select_next_strategy` at
every rotation boundary.  Held as `int` so the shm layout stays
language-stable across future enum reorders (same convention as
`plateau_rescue_amplified_class`).  Read by
`plateau_anti_prior_active()` on the hot pick path.  Reset to
`PIM_UNIFORM_RANDOM` on every non-intervention rotation so a stale
mode from a previous plateau cannot leave the anti-prior gate latched
on after the plateau lifts.

`plateau_intervention_rotation_counter` is a monotonic
per-intervention counter, bumped via `fetch_add` on every
plateau-window rotation; the selected mode is the (post-increment)
modulo against `NR_PIM_MODES`.  The counter only ticks while
`plateau_active` is set so each plateau intervention starts from
wherever the previous one left off -- adjacent plateaus separated by a
healthy stretch see the rotation pick up cleanly rather than always
re-running the same mode first.

`plateau_intervention_mode_windows[]` is a per-mode intervention-window
count.  Bumped at the same rotation site that selects the mode, so
end-of-run analysis can divide each mode's rescue yield by the windows
it actually ran without reconstructing the rotation history from the
`bandit_pulls_by_reason` matrix.

### Anti-prior mode fast path

`plateau_anti_prior_baseline_calls` caches the mean of
`kcov_shm->per_syscall.per_syscall_calls` across the currently-active syscall set
(biarch: `nr_active_32bit_syscalls + nr_active_64bit_syscalls`;
uniarch: `nr_active_syscalls`), refreshed by
`plateau_anti_prior_refresh_baseline()` at every rotation that selects
`PIM_ANTI_PRIOR`.  Read once per pick on the hot path inside
`plateau_anti_prior_accept()`.  Zero means "no baseline yet" (no
anti-prior rotation has fired, `kcov_shm` unavailable, or the active
pool is empty) and the accept gate short-circuits to "pass" in that
state so cold-start picks degenerate to uniform.

`plateau_anti_prior_accept_weight[MAX_NR_SYSCALL]` is the per-syscall
pre-computed acceptance numerator in
`[1, ANTI_PRIOR_THRESHOLD_SCALE]` (= 64 today), populated alongside
the baseline at every `PIM_ANTI_PRIOR` rotation.  The picker's
rejection roll reduces to `rnd_modulo_u32(SCALE) < weight[nr]`, which
lets the per-retry inner loop in `set_syscall_nr_random` skip the
clamp / divide / cap math the accept gate used to redo on every
candidate.  `uint8_t` suffices because `SCALE =
ANTI_PRIOR_MAX_BOOST^2 = 64` today and no per-syscall weight can
exceed `SCALE` by construction.

Visibility hand-off rides on the same RELEASE store of
`current_strategy` that publishes `plateau_intervention_mode_current`
-- the refresh runs from inside `select_next_strategy`, sequenced
before `maybe_rotate_strategy`'s release-store, so any picker that
ACQUIRE-loads `PIM_ANTI_PRIOR` also sees the matching weight table.
Stale weights from a previous `PIM_ANTI_PRIOR` window are harmless:
the `baseline=0` short-circuit only covers the never-refreshed state,
and subsequent rotations always overwrite both the baseline and the
array before the next release-store.

## Discounted "recent" counters for UCB1

The UCB1 picker scores these arrays instead of the lifetime
`bandit_pulls[]` / `bandit_reward_calls[]` series.  Kernel coverage
discovery is strongly non-stationary: easy edges are mined out in the
first windows of a run, the surface degrades over time, and any picker
that averages reward over the lifetime of the run lets early-window
wins dominate late-window arm selection forever.  Discounting the
counters with a rolling exponential weight keeps the picker responsive
to recent yield.

### Fixed-point encoding

Both arrays are fixed-point parts-per-thousand (suffix `_x1000`) so
the EMA arithmetic stays in unsigned-long integer math without
dragging a double into shm.  The exact alpha and the EMA update site
live in `strategy.c` (`BANDIT_EMA_ALPHA_X1000`); a half-life of
~10-30 windows is the design target so an arm whose yield collapses
after a configuration change (e.g. cgroup mount, netns unshare) loses
its grip on the picker within minutes rather than hours.

The arrays are:

- `recent_pulls_x1000[]` -- discounted effective sample count.  Each
  non-intervention window decays every arm by `(1 - alpha)` and adds
  `1.0` (== `BANDIT_EMA_SCALE`) to the active arm, so the asymptote
  for an always-picked arm is `SCALE/alpha` (20000 at alpha=0.05) and
  arms that stop being picked decay back toward zero over the
  half-life.

- `recent_reward_x1000[]` -- discounted total reward in the same
  fixed-point.  Mean per-window reward is
  `recent_reward_x1000[i] / recent_pulls_x1000[i]` (the x1000 cancels)
  so the UCB1 exploit term works without an explicit rescale step.

### Why decay every arm, not just the pulled one

Decaying EVERY arm each window (not just the pulled one) is what keeps
the UCB1 exploration term `n_i` denominator meaningful under
discounting: an arm that stops being picked must see its effective
sample count shrink so the explore bonus grows and the picker
eventually re-tries it.  EMA-on-pull-only (decay only the pulled arm)
would leave un-pulled arms' counts frozen forever, which breaks the
formula.

### SR_PLATEAU_FORCE skip

`SR_PLATEAU_FORCE` windows skip both the decay and the increment,
mirroring the lifetime `bandit_pulls[]` path: an intervention window
is not a learner observation, and bleeding intervention noise into
the discount cadence would shift every arm toward the post-plateau
distribution every time the orchestrator fires.

### Concurrency

Same CAS-serialised single-writer protocol as `bandit_pulls[]`;
`dump_strategy_stats()` uses RELAXED loads to tolerate the writer race
the same way it does for the lifetime fields.
