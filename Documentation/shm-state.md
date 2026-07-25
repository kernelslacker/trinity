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

## CLONE_NEWNET throttle

Trinity children fuzzing `fork()` / `clone()` / `clone3()` spawn
untracked grandchildren; each grandchild that calls `unshare` with
`CLONE_NEWNET` feeds the kernel's netns cleanup workqueue, and the
per-call cost grows with the queue's backlog.  Past a few in-flight
unshares per host the workqueue can't keep up -- `copy_net_ns()` begins
blocking in D-state, the untracked grandchild population grows
unbounded, and the box turns into a forkbomb.

`MAX_CONCURRENT_NEWNET` (4) caps the fleet-wide in-flight
`CLONE_NEWNET` caller count so the kernel-side workqueue can drain.
The sanitise hooks for `unshare` / `clone` / `clone3` bump
`shm->newnet_in_flight` on admission and the matching post hooks drop
it; calls that find the count already at the cap strip `CLONE_NEWNET`
from the flag arg instead of admitting another in-flight caller and
bump the `unshare_newnet_throttled` aggregate counter.

`newnet_in_flight` lives in shm so all children plus any untracked
grandchildren they fork share one counter -- a process-local static
would be duplicated across the COW fork tree and let each subtree run
its own unbounded admission rate.

### `try_admit_newnet()` -- single-CAS admission

Returns true iff the caller now owns one ticket against
`shm->newnet_in_flight`; the caller MUST stamp
`NEWNET_INFLIGHT_TICKET` onto `rec->post_state` and release with
`release_newnet_ticket()` from the post hook.  Returns false if the cap
is full -- caller strips `CLONE_NEWNET` and bumps the throttled stat.

A relaxed load followed by a separate `__atomic_fetch_add()` (the
shape the three call sites used to share) lets several callers all
observe the counter below the cap then all increment, over-admitting by
an entire wave.  CAS closes that window: the increment only commits if
the value we tested against is still what we read.

Unconditional `fetch_add` + rollback is not equivalent -- the transient
over-admission still feeds `copy_net_ns()` and is the whole thing the
cap exists to prevent.

### `release_newnet_ticket()` -- single-RMW release

Atomically clears `NEWNET_INFLIGHT_TICKET` on `rec->post_state` and
decrements `shm->newnet_in_flight` iff the bit was set on entry.
Idempotent: a second caller racing in observes the bit already cleared
and skips the decrement.

The race this guards against is raw `clone()` / `clone3()`: the kernel
returns in both the calling task and the newly created one, the
`syscallrecord` lives in shared memory (`children[]` ->
`alloc_shared`), and both branches run the post hook against the same
`post_state`.  A plain check-then-clear-then-decrement lets both
branches decrement for one admission, drifting the counter toward
negative and permanently disabling the cap.

`post_state` for `clone3` carries the args pointer in the high bits;
`fetch_and(~NEWNET_INFLIGHT_TICKET)` clears only bit 0 and leaves the
pointer intact for the post handler's downstream `deferred_freeptr()`.

## Per-childop feature-absent latches

Several `childops/net/*` childops build a kernel object inside a
transient `userns_run_in_ns()` grandchild, so the create/attach syscall
that would surface a missing `CONFIG_*` returns inside a `_exit()`ing
process.  A per-process static latch would die with the grandchild and
every subsequent invocation would re-attempt the same unsupported
kind forever (the "latch in grandchild" bug).  The fix is a fleet-wide
latch in `shm` per childop / per kind: first grandchild to observe the
absent-feature errno set flips the latch; siblings then skip the entry
so the unsupported attempt is paid once per fleet, not once per
grandchild.

RELAXED atomic load/store from multiple grandchildren is safe -- the
only transition is `false -> true` and the write is idempotent.  No
auto-clear; an absent kernel `CONFIG` does not appear mid-run, same
recovery story as the `sfg_unsupported[]` gates.

### `vxlan_encap_kind_unsupported[VXLAN_ENCAP_NR_KINDS]`

Per-kind gate for `vxlan_encap_churn` (`childops/net/vxlan-encap.c`).
Indexed by the file-local `enum tun_kind` (`0 = vxlan`, `1 = gre`,
`2 = geneve`) -- indices are PINNED by a `_Static_assert` in
`vxlan-encap.c`.  Set when `RTM_NEWLINK` rejects the kind with the
`rtnl_link_ops`-not-registered errno (absent module / CONFIG).

### `ip_gre_kind_unsupported`

Gate for `ip_gre_churn` (`childops/net/ip_gre-churn.c`).  Set when
`RTM_NEWLINK type=gretap` rejects with the `rtnl_link_ops`-not-
registered errno set (absent `CONFIG_NET_IPGRE` / module).

### `sctp_chunk_rx_kind_unsupported`

Gate for `sctp_chunk_rx` (`childops/net/sctp-chunk-rx.c`).  Set when
`socket(IPPROTO_SCTP)` rejects with `EPROTONOSUPPORT` /
`ESOCKTNOSUPPORT` / `EAFNOSUPPORT` / `EACCES` (missing
`CONFIG_IP_SCTP` / hardening policy blocking raw SCTP sockets in the
child's userns).

### `esp_crafted_rx_kind_unsupported`

Gate for `esp_crafted_rx` (`childops/net/esp-crafted-rx.c`).  Set when
`NETLINK_XFRM` open or `XFRM_MSG_NEWSA` installing a
null-cipher/null-auth ESP SA rejects with the `CONFIG_XFRM` /
`CONFIG_INET_ESP` / `CONFIG_INET6_ESP` absent errno set (`EOPNOTSUPP`
/ `EPROTONOSUPPORT` / `EAFNOSUPPORT` / `ENOPROTOOPT` / `ENOENT`).

### `fou_gue_mcast_rx_kind_unsupported`

Gate for `fou_gue_mcast_rx` (`childops/net/fou-gue-mcast-rx.c`).  Set
when `genl_open("fou")` or `FOU_CMD_ADD` installing a FOU/GUE receive
port rejects with the `CONFIG_NET_FOU` / `CONFIG_IPV6_FOU` absent
errno set (`ENOENT` / `EPROTONOSUPPORT` / `EAFNOSUPPORT` /
`EOPNOTSUPP` / `ENOPROTOOPT` / `EPERM`).

### `geneve_rx_kind_unsupported`

Gate for `geneve_rx` (`childops/net/geneve-rx.c`).  Set when
`RTM_NEWLINK kind="geneve"` installing a geneve tunnel dev rejects
with the `CONFIG_GENEVE` / module-absent errno set (`EAFNOSUPPORT` /
`EOPNOTSUPP` / `ENOTSUP` / `ENOENT` / `EPROTONOSUPPORT`).

### `bareudp_rx_kind_unsupported`

Gate for `bareudp_rx` (`childops/net/bareudp-rx.c`).  Set when
`RTM_NEWLINK kind="bareudp"` installing a bareudp tunnel dev rejects
with the `CONFIG_BAREUDP` / module-absent errno set (`EAFNOSUPPORT` /
`EOPNOTSUPP` / `ENOTSUP` / `ENOENT` / `EPROTONOSUPPORT`).

### `mpls_label_stack_rx_kind_unsupported`

Gate for `mpls_label_stack_rx` (`childops/net/mpls-label-stack-rx.c`).
Set when `/proc/sys/net/mpls/platform_labels` open returns `ENOENT`
(missing `CONFIG_MPLS_ROUTING` / `mpls_router` module).

### `espintcp_coalesce_kind_unsupported`

Gate for `espintcp_coalesce_churn`
(`childops/net/espintcp-coalesce-churn.c`).  Set when
`setsockopt(TCP_ULP, "espintcp")` rejects with the
`CONFIG_INET_ESPINTCP` absent errno set (`ENOPROTOOPT` /
`EOPNOTSUPP` / `EAFNOSUPPORT` / `EPERM`).

### `veth_xdp_kind_unsupported[VETH_XDP_NR_KINDS]`

Per-kind gate for `veth_asymmetric_xdp`
(`childops/net/veth-asymmetric-xdp.c`).  Indexed by the file-local
`enum pair_kind` (`0 = veth`, `1 = vxcan`, `2 = ipvlan`,
`3 = macvlan`) -- indices are PINNED by a `_Static_assert` in
`veth-asymmetric-xdp.c`.  Set when `RTM_NEWLINK` rejects the
pair/slave kind with the `rtnl_link_ops`-not-registered errno set.

### `veth_xdp_xdp_unsupported`

Companion gate for the same `veth_asymmetric_xdp` childop, latched
when `BPF_PROG_LOAD` rejects the XDP program with the
`CONFIG_BPF_SYSCALL` / `BPF_PROG_TYPE_XDP` absent or
`unprivileged-bpf-disabled` errno set (`EPERM` / `EACCES` /
`EINVAL` / `EOPNOTSUPP`).  Kept separate from
`veth_xdp_kind_unsupported[]` so a missing XDP facility doesn't
disable the per-kind asymmetric-queue exercise and a missing kind
doesn't disable XDP for the others.

## Multi-strategy syscall picker

The fleet runs one of `NR_STRATEGIES` picker arms at a time.  The
active arm rotates at every `STRATEGY_WINDOW` op-count boundary; the
first child to notice the boundary CASes the rotation forward and
carries out the switch.  Per-window edge-count bookkeeping feeds the
UCB1 learner; the field-level details live here so the header can hold
just the declarations.

### Rotation state

- `current_strategy` -- fleet-wide active strategy enum.  Children
  read it on every syscall pick (RELAXED atomic, single int read --
  cheap).  Updated only by the CAS-winning child at a rotation
  boundary.

- `current_selection_reason` -- `enum strategy_selection_reason` for
  the current arm: why `select_next_strategy()` returned that arm for
  this window.  Stored alongside `current_strategy` so the rotation
  site can read it back at window close and decide whether to feed the
  just-finished window into the UCB learner.  Forced-intervention
  windows (`SR_PLATEAU_FORCE`) skip the learner update so policy-
  chosen `RANDOM` windows and intervention `RANDOM` windows do not get
  conflated in `bandit_pulls[]` / `bandit_reward_calls[]`.  Held as
  `int` (not the enum) so the shm layout stays language-stable across
  any future enum reorder.

- `syscalls_at_last_switch` -- `shm_published->fleet_op_count` at the
  most recent rotation.  Doubles as the CAS guard: a child computes
  `(op_count - syscalls_at_last_switch)`, and if that crosses
  `STRATEGY_WINDOW` it tries to CAS this field forward to `op_count`.
  The CAS winner performs the strategy switch and emits the stats
  line; losers just continue with the new strategy on their next pick.

### Per-window edge-count snapshots

- `pc_edge_calls_at_window_start` / `pc_edge_count_at_window_start` --
  snapshots of `pc_edge_calls_by_strategy[prev]` and
  `pc_edge_count_by_strategy[prev]` taken at the previous switch.  Let
  the next switch compute the per-window deltas as
  `pc_edge_calls_by_strategy[prev] - pc_edge_calls_at_window_start`
  (call-count delta), and similarly for the bucket-count series.
  Written only by the CAS-winning child during a switch and read back
  by the next CAS-winning child; accesses are RELAXED-atomic so the
  cross-arch shared-memory discipline stays uniform with the
  surrounding per-strategy counter fields rather than relying on the
  CAS for ordering.

### Cumulative edge-count series

- `pc_edge_calls_by_strategy[]` -- cumulative count of SYSCALL CALLS
  attributed to each strategy whose post-call `kcov_collect()` flipped
  at least one never-seen bucket bit.  Bumped by `+1` per such call,
  NOT by the number of distinct edges that call uncovered: a syscall
  that exposes 50 fresh edges in one shot still bumps the call-count
  series by 1.  This series counts calls-with->=1-new-edge (not the
  edge count itself) and feeds the UCB1 learner via
  `bandit_reward_calls[]`.

- `pc_edge_count_by_strategy[]` -- cumulative count of REAL
  bucket-edge bits flipped by syscalls attributed to each strategy --
  the per-call `new_edge_count` from `kcov_collect()`, summed across
  all contributing calls.  Strictly `>=` the call-count series, often
  far larger when individual calls uncover deep paths.  Added
  alongside the call-count series so both signals are visible without
  changing the learner's behaviour; a future commit may switch UCB1 to
  consume this series instead, or fold a transform of it
  (e.g. `log2(1 + count)`) into the reward.

Cmp-mode runs do not produce a new-edge signal and are not attributed
to either series.

### UCB1 bandit picker (Phase 2)

- `picker_mode` -- arm-selection policy
  (`PICKER_ROUND_ROBIN` or `PICKER_BANDIT_UCB1`).  Set once at
  `init_shm` time from `picker_mode_arg`, never mutated thereafter.
  Read by the CAS-winning child on the rotation path.

- `bandit_pulls[]` -- number of windows each arm was selected for.
  Bumped by `bandit_record_pull()` during the rotation switch, which
  is serialised by the `syscalls_at_last_switch` CAS, so plain integer
  writes are safe (no concurrent writers).

- `bandit_reward_calls[]` -- cumulative reward attributed to each arm,
  in CALL-COUNT units -- sum of per-window
  `(pc_edge_calls_by_strategy delta + cmp_term)`.  The PC component
  counts CALLS that produced at least one new edge, not real bucket
  edges (see `pc_edge_calls_by_strategy` above).  This is the signal
  the UCB1 picker scores against.  The learner may later switch to
  consuming `bandit_reward_pc_edge_count[]` (real bucket count) or a
  transform of it; both signals are exposed so that choice can be made
  later.

- `bandit_reward_pc_edge_count[]` -- cumulative PC-edge BUCKET COUNT
  attributed to each arm -- sum of per-window
  `pc_edge_count_by_strategy` deltas, no cmp term folded in.
  Diagnostic-only today: visible alongside the call-count series in
  `dump_strategy_stats()` so the operator can see how the two signals
  would score the same set of windows differently before we commit to
  flipping the learner.

Both reward series are written under the same CAS-serialised rotation
path as `bandit_pulls[]`.

## Chaos-cohort observation counters

Chaos-mode V2 observation-only attribution.  Each completed window is
bucketed into `[arm][chaos_state]` in `bandit_record_pull`, where
`chaos_state` is the `cmp_hints_chaos_active` flag sampled at window
close (`chaos_off=0` / `chaos_on=1`).  The cohort split lets the
operator compare per-arm reward and kernel-diagnostic-fire rates
between windows where cmp_hints suppression was active and windows
where it was not, without re-running the fuzzer with chaos disabled.

Three parallel matrices mirror the existing lifetime series with a
chaos-state dimension:

- `bandit_pulls_by_chaos[a][c]` -- window count for arm `a` with chaos
  state `c`.  Bumped on every non-`SR_PLATEAU_FORCE` window the
  learner accepts; the per-cohort sum across `c` equals
  `bandit_pulls[a]`.

- `bandit_reward_calls_by_chaos[a][c]` -- combined reward
  (`pc_edge_calls + cmp_term`), same units as `bandit_reward_calls[a]`.
  Sum across `c` equals `bandit_reward_calls[a]`.

- `bandit_warn_fires_by_chaos[a][c]` -- per-window delta of
  `kmsg_warn_fires` bucketed into the matching cohort.  Brand new V2
  counter; no companion lifetime series because the headline V2
  question is "does chaos correlate with WARNs?" and a per-arm-flat
  WARN total without the cohort split would not answer it.

Observation-only -- nothing in `select_next_strategy` / `ucb1_score`
/ `pick_next_strategy` reads these arrays.  The learner's reward
formula in `bandit_record_pull` is unchanged.  Action mode (V3) will
fold the chaos-cohort signal back into the picker once the
statistical-significance gate from the design doc clears.

Single-writer protocol matches the existing `bandit_pulls[]` path
(CAS-serialised rotation); dump-side reads are RELAXED.
`NR_STRATEGIES * 2 * 3 series * 8 bytes = 192 bytes` today.

## Per-selection-reason attribution

Per-arm-per-selection-reason reward attribution.  Each window's
outcome is bucketed into `[arm][reason]` independent of the
learner-facing `bandit_pulls[]` / `bandit_reward_calls[]` series so
the operator and the future intervention classifier can see how each
arm's exposure splits across selection paths:

- `bandit_pulls_by_reason[a][SR_NORMAL_UCB]` -- arm `a` was chosen by
  the UCB1 scorer (the bandit's policy decision).
- `bandit_pulls_by_reason[a][SR_COLD_START]` -- arm `a` was chosen
  because UCB1 had not seen it pulled yet.
- `bandit_pulls_by_reason[a][SR_ROUND_ROBIN]` -- arm `a`'s slot in the
  fixed cycle (round-robin mode only).
- `bandit_pulls_by_reason[a][SR_PLATEAU_FORCE]` -- arm `a` (always
  `STRATEGY_RANDOM` today) was forced by the intervention orchestrator
  over the top of the bandit's pick.  These windows are deliberately
  EXCLUDED from `bandit_pulls[]` and the `recent_*_x1000` EMA so the
  learner's view of `RANDOM` stays uncontaminated, but they ARE
  recorded here so the operator can see the intervention cohort's
  reward separately and a future plateau-rescue classifier can read
  `pulls_by_reason[*][SR_PLATEAU_FORCE]` +
  `pc_edge_calls_by_strategy[*]` to decide which arm to force next
  time.

Three parallel matrices mirror the lifetime series:

- `bandit_pulls_by_reason[a][r]` -- window count.
- `bandit_reward_calls_by_reason[a][r]` -- combined reward
  (`pc_edge_calls + cmp_term`), same units as `bandit_reward_calls[]`.
- `bandit_reward_pc_edge_count_by_reason[a][r]` -- real bucket-edge
  count, same units as `bandit_reward_pc_edge_count[]`.

Same single-writer protocol as `bandit_pulls[]` (CAS-serialised
rotation path).  `dump_strategy_stats()` uses RELAXED loads.
`3 strategies * 4 reasons * 3 series * 8 bytes = 288 bytes`, trivial
against existing shm consumers.

## Random-rescue classifier

`random_rescue_class_count[RRC_NR_CLASSES]` -- classifier counters
(see `classify_random_rescue` in `include/strategy.h`).  Each
new-edge syscall completed during an `SR_PLATEAU_FORCE` window is
classified into one of the `RRC_*` buckets and the corresponding slot
here is bumped.  The cumulative distribution is what the next plateau
intervention reads to decide whether plain `RANDOM` is still the right
rescue arm or whether the classifier has accumulated enough evidence
to point at a more targeted intervention (cold-skip disable, cmp-hint
boost, etc.).

Multi-producer (every child that completes a rescue increments its
class slot); RELAXED `fetch_add` on the write side, RELAXED loads on
the orchestrator-side reads in `select_next_strategy` and
`dump_strategy_stats`.  Per-class cacheline contention is acceptable:
the writer set is small (only children whose syscall landed in a
forced-intervention window and produced new edges) and the readers
consult these counts at rotation boundaries and at end-of-run, not on
the hot pick path.

### `plateau_rescue_amplified_class`

Currently-amplified random-rescue class, published by the orchestrator
(`select_next_strategy`) at every rotation boundary.  `RRC_NR_CLASSES`
is the "no amplification" sentinel -- either the fleet is not in a
plateau intervention or no class has cleared the dominance threshold
against its peers.  Held as `int` (not the enum) so the shm layout
stays language-stable across any future enum reorder, same convention
as `plateau_current_hypothesis`.

Read by children on the hot pick / arg-generation path to
conditionally relax structured filters that the classifier blamed for
the recent rescue cohort:

- `RRC_COLD_SKIP` -> `set_syscall_nr_heuristic` skips its
  `kcov_syscall_cold_skip_pct` retry, so cold syscalls flow through
  the heuristic arm during the intervention.
- `RRC_CMP_DERIVED` -> `generate-args.c`'s 1-in-16
  `cmp_hints_try_get` rolls flip to 1-in-4 so the learned constants
  the classifier credited the rescues to fire more often.

Gated on
`(shm->plateau_active && current_selection_reason == SR_PLATEAU_FORCE)`
at every read site so the relaxation applies only inside the
intervention window, never as a permanent change to the structured
pickers.

## Wall-lever shadow gate

Identifies high-call zero-yield syscalls during a warm-plateau window
so a future live variant can reclaim their pick budget for productive
/ cold syscalls.  Held in shm next to the anti-prior cache because the
publish ordering and the rotation-boundary refresh discipline are
identical.

- `wall_lever_baseline_calls` -- cached mean of
  `kcov_shm->per_syscall.per_syscall_calls` across the active syscall
  count (biarch:
  `nr_active_32bit_syscalls + nr_active_64bit_syscalls`; uniarch:
  `nr_active_syscalls`; mirrors `no_syscalls_enabled`).  Refreshed by
  `wall_lever_refresh_baseline()` on every rotation where
  `plateau_active` is set, BEFORE the mode-specific arm dispatch.
  Zero means "no baseline yet" (no plateau-active rotation has fired,
  or no syscalls are active) and the shadow predicate short-circuits
  to "not suppressed" in that state so warm-up runs and the cold-start
  window degrade to today's pure picker.

- `wall_lever_suppress[MAX_NR_SYSCALL]` -- per-syscall pre-computed
  suppression decision in `{0, 1}`, populated alongside the baseline
  at every plateau-active rotation.  Picker-side shadow gate reads a
  single RELAXED byte per candidate -- the clamp / multiply / compare
  math lives in the refresh path so the per-pick cost is one load and
  one branch.  `uint8_t` suffices because the field is a boolean
  carrier.  Visibility hand-off rides on the same RELEASE store of
  `current_strategy` that publishes
  `plateau_intervention_mode_current` -- mirrors
  `plateau_anti_prior_accept_weight`'s publish ordering.

## Plateau-hypothesis mirror

`plateau_current_hypothesis` is the shm mirror of `strategy.c`'s
parent-private `hypothesis_current`.  Published by
`strategy_plateau_hypothesis_tick()` (parent only) at every stats
tick; read RELAXED by `select_next_strategy()` on every rotation to
gate the targeted intervention selection.

`PLATEAU_HYPOTHESIS_NONE` means "no rule matched" or "no plateau
active" -- both cases revert to the round-robin intervention path.
Held as `int` (not the enum) so the shm layout stays language-stable
across any future enum reorder, same convention as
`plateau_rescue_amplified_class`.

The gate is a derived predicate over this field, not a latched flag:
when `plateau_active` falls and the tick driver writes `NONE` here,
the next `select_next_strategy` rotation reverts to round-robin
automatically.  No standalone activation/deactivation state to keep in
sync.

## Cmp-novelty bloom + reward

Cmp-hint novelty attribution for the UCB1 learner -- see
`bandit_cmp_observe` in `include/strategy.h`.

### `bandit_window_count`

Monotonic rotation counter, bumped by the CAS-winning child in
`maybe_rotate_strategy()` once per completed window.  Used as the
generation tag for the `cmp_novelty[]` bloom decay: a bloom entry with
`window_tag` more than `CMP_NOVELTY_DECAY_WINDOWS` behind this counter
is considered stale and gets cleared on next access.  Stays plain
`unsigned long` with explicit `__atomic_*` accessors to match the
existing `bandit_pulls[]` / `bandit_reward_calls[]` convention.

### `cmp_novelty[MAX_NR_SYSCALL][2]`

Per-syscall comparison-constant novelty bloom.  Each entry holds a
1024-bit bloom filter over the comparison constants observed for that
syscall in the recent past, plus a generation tag (the rotation count
at which the bloom was last cleared).  When a child observing a fresh
CMP record finds the entry's tag more than `CMP_NOVELTY_DECAY_WINDOWS`
rotations old it lazily zeroes the bloom and republishes the tag, so
a constant that stops appearing for `K` windows is forgotten and
counts as novel again.  Sized `132 bytes * MAX_NR_SYSCALL ~= 132 KiB`
inside shm -- well below other arrays already living here
(`per_syscall_*`).

Indexed by `[syscall_nr][do32 ? 1 : 0]`.  Biarch builds split the
novelty bloom per arch so 32-bit `nr=N` and 64-bit `nr=N` (which may
be unrelated calls) do not poison each other's per-syscall
constant-novelty signal.  Uniarch builds only touch `[*][0]`.

### `bandit_cmp_new_constants[NR_STRATEGIES]`

Per-arm cumulative count of CMP records that missed the bloom at
observation time.  Bumped by every child inside `bandit_cmp_observe()`
(atomic add, multiple producers).  The rotation hook turns the
per-window delta into a secondary reward term inside
`bandit_record_pull()`.

### `bandit_cmp_at_window_start`

Snapshot of `bandit_cmp_new_constants[active_arm]` at the start of the
current window, by symmetry with `pc_edge_calls_at_window_start`.  The
rotation hook reads `bandit_cmp_new_constants[prev]` and subtracts
this snapshot to compute the cmp-novelty delta the just-finished
window produced, then reseeds the snapshot from the next arm's
counter.  Single field rather than per-arm because only one arm is
active per window.  Written only by the CAS-winning child and read
back by the next; accesses are RELAXED-atomic to keep the shared-
memory discipline uniform with the companion `*_at_window_start`
fields rather than relying on the CAS for cross-arch ordering.

### `kmsg_warn_fires_at_window_start`

Snapshot of `kcov_shm->kmsg.kmsg_warn_fires` at the start of the
current bandit window.  Single global field (mirrors
`bandit_cmp_at_window_start`) because `kmsg_warn_fires` is global
rather than per-arm -- the chaos-cohort attribution that consumes the
delta needs only "how many WARNs fired in this window", not "how many
WARNs fired while strategy X was active".  Reseeded from the live
counter at every rotation regardless of selection reason, so the delta
the cohort split sees represents only events the kernel emitted inside
the just-finished window.  Written only by the CAS-winning child on
the rotation path; RELAXED accesses match the other
`*_at_window_start` fields.

### `bandit_cmp_share_sum_x1000[NR_STRATEGIES]`

Per-arm cumulative sum of `(cmp_term * 1000 / total_reward)` across
windows where `cmp_term > 0`.  Divided by `bandit_pulls[arm]` at end
of run to print the average per-window CMP contribution share, so the
operator can tune `CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL` on real run
data.  Written only by the CAS-winning child, same path as
`bandit_pulls` / `bandit_reward_calls`.

## Coverage-frontier picker state

Per-syscall frontier-edge ring -- see `include/strategy.h`.  The
coverage-frontier picker biases its uniform pick by each syscall's
recent NEW-edge count.

### `frontier_history[MAX_NR_SYSCALL][FRONTIER_DECAY_WINDOWS]` + `frontier_slot`

`frontier_history[nr][slot]` counts NEW edges syscall `nr` produced
during the rotation window mapped to `slot`.  Slot is an index in
`[0, FRONTIER_DECAY_WINDOWS)`; the slot currently being filled is
`(frontier_slot & mask)`, advanced once per rotation by the
CAS-winning child via `frontier_window_advance()`.  Sum across all
slots is the syscall's "recent frontier-edge count" -- the weight the
coverage-frontier picker biases its uniform pick toward.

Bumped on the `kcov_collect` new-edge branch by every child
(multi-producer, atomic add).  Slot rotation zeroes the new slot
before publishing the new index, so a producer racing the rotation
either bumps the previous (still-valid) slot or the freshly cleared
new slot -- both attribute correctly within the K-window decay.

Sized `MAX_NR_SYSCALL * FRONTIER_DECAY_WINDOWS * 4 = 32 KiB`, a
rounding error against the `cmp_novelty[]` block above.

### `frontier_recent_count_cached[MAX_NR_SYSCALL]`

Per-syscall cached recent-edge count -- running sum of
`frontier_history[nr][*]` across the live ring, maintained
incrementally so `frontier_recent_count(nr)` is a single RELAXED load
instead of an `O(FRONTIER_DECAY_WINDOWS)` walk.  Producers `fetch_add
1` here in lockstep with the per-slot bump; the window rotator
subtracts the just-zeroed slot's contribution from this counter in the
same pass that clears the slot.  Same RELAXED race envelope as
`frontier_history` -- a producer add that interleaves with the
rotation's exchange-then-subtract can leave cached one bump above the
live sum, bounded by one window and folded back in by the next
rotation.

### `frontier_max_weight_cached`

Cached max of `frontier_recent_count()` across all syscalls -- the
rejection-sampling acceptance ratio in the coverage-frontier picker
uses this as the bias-mass denominator.  Recomputed authoritatively on
each window rotation, and ratcheted upward on new-edge bumps, so the
picker reads it with a single RELAXED load instead of walking
~`MAX_NR_SYSCALL` frontier rings (8 RELAXED loads each) per pick.
Torn / stale values are acceptable: a slightly low cached max biases
the picker toward heavier-weighted syscalls (under-rejecting cold
ones); a slightly high one biases it toward uniform.  Both errors are
bounded by one window rotation.

## Data-segment externs

Global pointers paired with the shm state but living in the normal
data segment (NOT in shm), so each forked process gets its own COW
copy.  A stray child write to any of these pointers corrupts only that
one child's copy and cannot zero out the pointer for parent or
siblings.

- `children` -- global pointer to the per-child `struct childdata`
  array.  The pointed-to array is `mprotect`ed `PROT_READ` in
  `init_shm()` so its contents are also protected.

- `childdata_mapping_len` -- length of each per-child `childdata`
  mapping in bytes.  Set once by `init_shm_per_child_rings()` to
  `sizeof(struct childdata)` rounded up to a page multiple, so
  `freeze_sibling_childdata`'s `mprotect()` call covers exactly the
  span the mapping owns.  Kept in the parent's data segment
  (inherited COW-per-child) so a wild write to the variable in one
  child cannot perturb another child's freeze length.

- `expected_fd_event_rings` -- canary copy of each child's
  `fd_event_ring` pointer, taken at init time so wild-write damage to
  the per-child ring pointer can be detected.  `fd_event_drain_all()`
  compares the live pointer against this array; a mismatch means the
  pointer was overwritten after init, and we use the known-good value
  to keep draining while logging the incident.

- `expected_stats_rings` -- canary copy of each child's `stats_ring`
  pointer, same detection story as `expected_fd_event_rings`;
  `stats_ring_drain_all()` compares the live pointer against this
  array on drain.

### `NEWNET_INFLIGHT_TICKET` bit encoding

Low-bit ticket the throttle stamps onto `rec->post_state` after a
successful admission.  `clone3` packs the args pointer in the high
bits of `post_state`; `zmalloc` returns >=8-byte-aligned pointers, so
bit 0 is free.  `unshare` and `clone` leave the rest of `post_state`
as zero, so the same bit overlays cleanly there too.
