# Strategy design notes

Companion to `include/strategy.h` (and the `strategy*.c` implementation
files it declares).  The header keeps enum values, function contracts,
per-tunable one-line descriptions, and load-bearing invariants inline;
this document collects the multi-paragraph design rationale those inline
pointers refer to.  Sections are ordered roughly to match declaration
order in the header.

## Multi-strategy syscall-selection rotation

Each strategy implements a distinct `pick_syscall` policy.  Different
strategies have different blind spots; rotating through them surfaces
bug classes that any single policy systematically suppresses.

The active strategy is fleet-wide (single shm-resident enum, every child
reads it on each syscall pick) and rotates every `STRATEGY_WINDOW` ops.
The arm-selection policy itself is pluggable (see `enum picker_mode_t`
in the header): Phase 1 shipped a fixed round-robin; Phase 2 adds a UCB1
bandit picker that consumes the per-strategy edge-attribution counters
as the reward signal.

Per-strategy edge attribution is recorded in two parallel series --
`shm->pc_edge_calls_by_strategy[]` (calls that produced >=1 new edge)
and `shm->pc_edge_count_by_strategy[]` (real bucket-edge counts) -- so
the operator can compare strategies across many windows.  The bandit
picker currently derives its reward signal from the call-count series;
the bucket-count series is recorded in parallel so the alternative
reward shape is visible without changing the learner's behaviour.

Today's arms are heuristic, uniform random, and coverage-frontier (see
`enum strategy_t`); each becomes an arm the bandit picker scores against
the others.  Future arms under consideration (group-saturation,
newly-discovered, genetic) slot into the same dispatch -- adding one is
an enum entry plus a `pick_syscall` hook.

## Silent-streak shadow decay (FRONTIER_SHADOW_DECAY_STREAK)

Threshold for the per-syscall silent-streak accounting in the
coverage-frontier picker.  The picker bumps a per-syscall counter
(`stats.frontier_silent_streak_per_syscall[]`) on every accepted pick
that lands in the silent-ring regime (`max_weight <= 2`, the defining
state of a coverage plateau), and resets that counter to zero from
`frontier_record_new_edge()` on the per-syscall new-edge productive path
in `kcov_collect`.  Crossing the threshold bumps the global
`stats.frontier_shadow_decay_candidates` exactly once per crossing --
the headline observability stat that estimates how many syscalls a
future LIVE decay variant of the picker would treat as decay
candidates, computed WITHOUT changing any selection today.

Read by:
- `random-syscall.c` -- silent-regime bump site, compares post-increment
  streak against this threshold.
- `stats.c` -- periodic dump emits the threshold value alongside the
  candidate count so the operator can interpret the count.

NOT read by any picker accept/retry / scoring / weight math.  Adjusting
the value cannot perturb the live frontier distribution.  Conservative
default of 64: eight ring-widths (`FRONTIER_DECAY_WINDOWS`) of
CONSECUTIVE silent-regime picks of the same syscall without one new
edge for it -- a clearly-stuck candidate even allowing for short-run
unlucky streaks.

## Per-syscall LIVE-regime miss-streak cooldown (FRONTIER_LIVE_MISS_COOLDOWN)

Counts CONSECUTIVE LIVE-regime frontier picks of the same syscall that
earned no new PC edge -- the per-syscall counterpart to the global
`frontier_live_misses_per_syscall[]` kill-list signal.  Reset to zero on
any productive event (PC edge or transition slot flip) via the existing
`frontier_record_new_edge` / `_record_transition_edge` hooks, so the
streak captures the run-length of zero-edge LIVE-regime picks since the
syscall last earned coverage.

When the streak transitions through this threshold the global
`frontier_live_cooldown_candidates` counter edge-bumps once for this
episode; every subsequent LIVE-regime miss past the threshold bumps
`frontier_live_would_skip` cumulatively.  Together they project the
pick-budget a future LIVE-regime cooldown variant of the picker would
reclaim from warm zero-edge syscalls (`mlock` / `unshare` / `mincore`
et al) without changing what the live picker selects today.

NOT read by any picker accept/retry / scoring / weight math.  Adjusting
the value cannot perturb the live frontier distribution.  Conservative
default of 4: four consecutive zero-edge LIVE-regime picks of the same
syscall is a clear "the live ring keeps biasing here but it never
converts" signal -- the cooldown candidate set the future suppression
lever scores against.

## LIVE-regime blanket reject denom (FRONTIER_LIVE_DECAY_REJECT_DENOM)

Companion to `FRONTIER_SILENT_DECAY_REJECT_DENOM` but inverted: the
silent gate fires only on decay-classified syscalls with
`REJECT_DENOM-1 / REJECT_DENOM` probability, this gate fires
UNCONDITIONALLY on every LIVE-regime pick with `1 / REJECT_DENOM`
probability so the live ring reclaims ~3% of its wasted budget without
depending on any per-syscall classification.

The blanket reject is intentionally isolated from the per-syscall
cooldown signal (`frontier_live_miss_streak_per_syscall[]` and its
scalar companions): the targeted variant that gates on the cooldown
predicate is a SEPARATE later commit, because the cooldown predicate
indirectly depends on the LIVE-regime ring shape (a syscall the picker
stops sampling stops accumulating misses) and bootstrapping the two
together would compound risk on the first ramp.  This commit's reject
reclaims live-ring budget WITHOUT touching the cached weight, the
ring-decay loop, or the cooldown predicate -- the smallest possible
behaviour change that produces the desired reclaim.

Denominator value matches `FRONTIER_SILENT_DECAY_REJECT_DENOM` /
`FRONTIER_ERRNO_PLATEAU_REJECT_DENOM` / `CRED_THROTTLE_REJECT_DENOM` so
the three live-rejection gates share a single tunable shape; the
inversion is in the `rnd_modulo_u32` comparison at the call site
(`== 0` here vs `!= 0` in the silent gate), not in the denominator.

## Errno-plateau decay predicate (FRONTIER_ERRNO_PLATEAU_*)

A syscall whose lifetime call count has accumulated past
`FRONTIER_ERRNO_PLATEAU_MIN_CALLS` without ever producing a PC edge, a
transition slot flip, or a CMP-pool insert -- AND whose returns are
dominated `>= _DOM_PCT` by a single non-SUCCESS errno bucket -- is
classified as wasting silent-regime picks: the picker is repeatedly
steering toward a syscall the kernel has shown it will reject with the
same errno every time, and that rejection has yet to translate into any
coverage signal.  Worst offenders observed (`tee` 95k `EBADF`/`EINVAL`
0-edge; `userfaultfd` 93k `EPERM` 0-edge; `process_mrelease` 0-success)
all match this shape.

`REJECT_DENOM` matches `CRED_THROTTLE_REJECT_DENOM` (31/32 == ~96.875%
rejection) so the cohort that flips to the live decay still samples the
syscall at ~3% -- recoverable on any one of:

- PC-edge novelty (`per_syscall_edges[nr]` becomes `> 0`)
- transition novelty (`per_syscall_transition_edges_real_local[nr] > 0`)
- CMP novelty (`per_syscall_cmp_inserts[nr] > 0`)
- new-errno novelty (a fresh bucket dilutes the dominant ratio below
  `DOM_PCT`, including a late SUCCESS)

The predicate is checked per-pick against monotonic counters, so any of
the above flips it permanently false for the syscall without needing a
per-syscall reset hook.

The credential-class syscall set already has its own EPERM/EINVAL
dominance throttle (`--cred-throttle` /
`cred_throttle_should_reject`); `frontier_errno_plateau_should_decay()`
excludes that set so a credential syscall cannot be decayed by both
gates simultaneously.

## Saturation-cooldown magnitude gate (FRONTIER_SATCOOL_CMIN)

A syscall the picker has tried fewer than this many times across its
accumulated lifetime counters is treated as still under-explored and is
spared from the cooldown regardless of plateau / spare-lane outcomes --
many of the struct-arg sanitiser backlog (`removexattrat` /
`listxattrat` / `futex` / `fcntl`) sits in the 1k..4k lifetime-call
range and looks identical to a saturated-rich syscall on PC-edges
alone; gating on magnitude keeps the cooldown from demoting them
before arg-gen has had time to break through.

10000 is ~4x uniform on the surface this picker sees (~2500
calls / syscall / run at default rates), which clears every observed
struct-arg backlog member while sitting well below the saturated-rich
set's per-run pick budget (`syncfs` / `sendfile` / `semget` / `writev`
all measured at 10k+ calls in the run-1439 baseline).  Tunable from the
SHADOW-ONLY `frontier_satcool_would_skip_per_syscall[]` readout once
that runs.

## Saturation-cooldown mode (frontier_saturation_cooldown_mode)

Gates the corrected per-syscall plateau-cooldown predicate the
coverage-frontier picker's silent-regime accept site evaluates -- a
sibling of the existing silent-streak (`frontier_decay_*`) and
errno-plateau (`frontier_errno_decay_*`) shadow predicates, with the
predicate semantics fixed against the structural blind-spot the
existing silent-streak decay has on `syncfs`-class syscalls (raw
`ERRNO_BUCKET_SUCCESS` count is monotonic on a perpetually-succeeding
syscall, so the existing UNLESS clause's errno-baseline equality test
never trips and the streak never reaches the decay).

Mode ramp:

- **OFF** -- default, byte-identical to today.  The silent-regime
  accept site skips the satcool predicate evaluation entirely; no
  shadow counters bump, no syscall-entry lookup runs, no reject path
  exists.
- **SHADOW_ONLY** -- compute the corrected predicate in shadow inside
  the silent-regime accept block and bump the `frontier_satcool_*`
  counters.  Selection stays byte-identical -- no goto-retry branch is
  gated on the predicate.  Read the per-syscall would-skip array to
  confirm the demote mass concentrates on the saturated-rich set
  (`syncfs` / `sendfile` / `semget` / `writev`) and is ~0 on the
  struct-arg backlog (`removexattrat` / `futex` / `io_uring_setup` /
  `bpf`) before tuning `C_min` or promoting COMBINED.
- **COMBINED** -- reserved.  The enum value exists so future commits
  that wire the live reject can land without renumbering the enum, but
  THIS COMMIT does NOT implement the live reject -- selecting combined
  today behaves identically to shadow-only (the predicate is computed
  and counters bump, no goto-retry fires).  Wiring the live reject is
  a separate follow-up after SHADOW_ONLY validates `C_min` and the
  spare lanes against a real run.

Param-settable from
`--frontier-saturation-cooldown=off|shadow-only|combined`; mirrors the
`kcov_transition_reward_mode` shape so a reader familiar with that knob
(and its SHADOW->COMBINED ramp) recognises the rollout discipline.

## LIVE-regime cooldown magnitude floor (FRONTIER_LIVE_COOL_CMIN)

Sibling of `FRONTIER_SATCOOL_CMIN` for the silent-regime satcool
predicate; deliberately MUCH smaller because the productive syscalls
the live cooldown over-cools today sit far below the satcool 10000
mark (`bpf` / `openat` / `io_uring_setup` / `io_setup` at 775..2813
calls; `futex` / `setxattrat` in the same range as struct-arg backlog
members).  Reusing `FRONTIER_SATCOOL_CMIN` here would gate the spare
lanes out for the entire productive set the discriminator is meant to
spare, and would simultaneously leave the legitimately-barren `gettid`
(9.5k) below the magnitude bar so the live cooldown could never fire
on it either -- the opposite of the lever's intended split.  256 keeps
the `gettid` / `sched_get_priority_max` getters (9.5k / 22.8k)
cool-eligible while keeping the magnitude floor large enough that a
syscall with only a handful of picks cannot be classified as cooled on
a statistically-meaningless sample.  A/B-tunable from the SHADOW-only
`frontier_live_cool_would_skip_per_syscall[]` readout once that runs.

## LIVE-regime cooldown discriminator (frontier_live_cooldown_mode)

Sibling of `frontier_saturation_cooldown_mode`; ports the satcool
spare-lane predicate INTO the LIVE-regime cooldown decision so the live
cooldown cools only the truly-barren/saturated and SPARES the
productive (object-producers + mid-breakthrough struct-args + bpf-class
syscalls whose K-window ring is still nonzero).  The existing
LIVE-regime cooldown gate (per-syscall miss-streak
>= `FRONTIER_LIVE_MISS_COOLDOWN`) keys on a single signal -- a
miss-streak of 4 consecutive zero-edge LIVE picks is trivially reached
by a productive syscall between its rare edge-finding picks, so the
live cooldown over-demotes producers and mid-breakthrough struct-arg
syscalls alongside the genuinely barren getters.  This mode adds the
spare-lane discriminator (windowed-edges / arggen-progress /
object-producer) to the cool decision so the split lands on the right
axis.

Mode ramp:

- **OFF** -- default, byte-identical to today.  The LIVE-regime
  miss-streak attribution path skips the discriminator evaluation
  entirely; no `kcov_shm` load, no spare-lane computation, no new
  shadow counters bump.
- **SHADOW_ONLY** -- compute the discriminator at the LIVE-regime miss
  attribution path and bump the `frontier_live_cool_*` shadow counters
  split by spare reason.  Selection stays byte-identical -- the
  existing `frontier_live_would_skip` projection (undiscriminated)
  keeps bumping in parallel, so the
  `(live_cool_would_skip / live_would_skip)` ratio reads exactly how
  much over-cool the discriminator removes.  Read the per-syscall
  `would_skip` / `would_spare` arrays to confirm the demote mass
  concentrates on `gettid` / `sched_get_priority_max` and is ~0 on
  `bpf` / `io_uring_setup` / `openat` / `io_setup` / `futex` /
  `setxattrat` before promoting COMBINED.
- **COMBINED** -- reserved.  The enum value exists so the live
  divergence wire-up (rotation-loop halving at
  `strategy-frontier.c::frontier_window_advance` and the per-syscall
  miss-attribution reject) can land in a follow-up commit without
  renumbering the enum, but THIS COMMIT does NOT implement the live
  divergence -- selecting combined today behaves identically to
  shadow-only (discriminator evaluates and counters bump, no live
  cooldown decision is gated on the discriminator).  Mirrors the OFF /
  SHADOW_ONLY / COMBINED ramp discipline the sibling
  `frontier_saturation_cooldown_mode` uses.

Param-settable from
`--frontier-live-cooldown-mode=off|shadow-only|combined`; independent
of the LIVE-regime rotation-loop halving in
`frontier_window_advance()`, which is always on.

## F-RSEQ -- heuristic-arm group-bias anti-lock-in damper

Sibling of the frontier-arm saturation cooldown; the two cooldowns
split along the two picker arms (frontier vs heuristic) and reclaim
the two halves of the no-input call budget that the run-1717
measurements decomposed (one no-arg / never-fail `GROUP_PROCESS`
member absorbing ~20-28k calls/run via the sticky `last_group` +
70%-same-group retry loop in
`random-syscall.c::set_syscall_nr_heuristic`; rotates by seed but
always collapses onto pure getters / no-op yields because those are
the only `GROUP_PROCESS` members that pass every gate cheaply and
re-arm the pin).  The damper releases a BARREN group pin (one whose
windowed coverage productivity is flat AND which holds no live object
mid-setup) so the draw escapes the junk-drawer, while preserving
productive group clustering (`NET`
`socket->bind->sendto`, `VFS` `open->read->close`) precisely because
productive pins advance the coverage watermark on every yielding
member and so never go stale within the window.  See the windowed-pin
predicate body in `random-syscall.c` and the per-group / per-syscall
would-skip counters in `include/stats.h` for the shape this evaluates
and counts in shadow.

### Discriminator

The property that distinguishes productive clustering from one no-op
monopolising the pin: the predicate keys on PER-PIN PRODUCTIVITY --
the watermark advances when this call found a new PC-edge or a new
local transition-edge, so a group running a stateful sequence keeps
producing within the window and is never released, while a pin
dominated by pure observers (no edges, no transitions, no object) goes
barren past the window and is released.  The `pin_warm` spare folds
in the warm-setup case (`NET` / `VFS` / `io_uring` chains that run
many edge-less known-setup calls before the rare trigger): a pin that
produced an fd this streak is spared even when coverage-barren,
because the produced object is the locality the bias is really
protecting.  Per-syscall would-skip mass concentrating on
`rseq_slice_yield` / `getpgrp` / `sched_yield` and per-group mass
concentrating on `GROUP_PROCESS` (=5) is the SHADOW_ONLY headline
confirming the predicate targets the documented pathology and leaves
NET/VFS clusters untouched.

### State keying

Predicate state is PER-CHILD and PER-NR for the per-syscall shadow
counter (`last_group` is already per-child, and the per-syscall
would-skip array key is `nr` alone).  No `(nr, context_id)` re-keying
in this row -- pools P2.5 introduces `context_id` later and the
per-syscall would-skip key participates in that sweep along with
cold-skip / cred-throttle / satcool.  Until then, `context_id ==
regular` for every child so the per-nr key is counter-identical to a
`(nr, regular)` key.

### Bookkeeping order

Owner-only writes from the `dispatch_step` tail
(`account_fd_and_group`), gated on
`frontier_group_antilock_mode != OFF` and on `group_bias`.  Order:

- On `entry->group != child->last_group` (group changed) -> reset
  `group_streak_len`, `last_cov_at_streak`,
  `group_fd_created_in_streak` to 0.
- ALWAYS `group_streak_len++` after the potential reset.
- ON found-local-coverage (new PC-edge OR new local transition-edge)
  -> `last_cov_at_streak = group_streak_len`.
- ON `entry->rettype == RET_FD` with `rec->retval != -1UL` ->
  `group_fd_created_in_streak++`.

No cross-process coherence needed; no shm, no atomics.

### Mode ramp

- **OFF** -- default, byte-identical to today.  The `dispatch_step`
  bookkeeping (group-change streak reset, fd-warm bump, coverage
  watermark advance) and the `group_bias`-gate shadow predicate
  evaluation are ALL gated on this mode; under OFF no per-child field
  is read or written, no atomic loads run, no shadow counters bump.
- **SHADOW_ONLY** -- bookkeeping runs (per-child only, no shm) and the
  shadow predicate evaluates at the `group_bias` gate, bumping the
  `frontier_frseq_*` shadow counters.  Selection stays byte-identical
  -- no goto-retry branch is gated on the predicate.  Read the
  per-syscall and per-group would-skip arrays to confirm the demote
  mass concentrates on `rseq_slice_yield` / `getpgrp` / `sched_yield`
  and on `GROUP_PROCESS` before tuning `MIN_STREAK` / `COV_WINDOW` or
  promoting COMBINED.
- **COMBINED** -- reserved.  The enum value exists so the live
  pin-release wire-up can land in a follow-up commit without
  renumbering the enum, but THIS COMMIT does NOT implement the live
  release -- selecting combined today behaves identically to
  shadow-only (predicate computed, counters bump, gate unchanged).
  Mirrors the OFF / SHADOW_ONLY / COMBINED ramp discipline the sibling
  `frontier_saturation_cooldown_mode` uses.

Param-settable from
`--frontier-group-antilock=off|shadow-only|combined`.

### Group-pin damper thresholds

`FRONTIER_FRSEQ_MIN_STREAK` and `FRONTIER_FRSEQ_COV_WINDOW` are tuned
to protect legitimate warm-setup clustering: a pin needs at least
`MIN_STREAK` heuristic picks before it can be considered for release,
and within that pin the watermark gap (current streak position minus
the most recent coverage credit within the pin) must exceed
`COV_WINDOW` before the pin counts as stale.  The `COV_WINDOW` is
intentionally generous (`NET` / `VFS` / `io_uring` chains can run many
edge-less known-setup calls between a `socket()` / `openat()` and the
rare trigger; that spare additionally lives in the `pin_warm`
fd-liveness path); a `GROUP_PROCESS` pure-getter pin advances the
watermark NEVER, so after `MIN_STREAK + COV_WINDOW` picks it goes
stale regardless of how generous `COV_WINDOW` is.  Sweepable from the
SHADOW_ONLY `frontier_frseq_would_skip_per_syscall[]` readout once
that runs.

## Cost-pool one-shot selector (cost_pool_selector_mode)

Sibling of `frontier_saturation_cooldown_mode` /
`frontier_group_antilock_mode`.  Governs whether the random-syscall
picker's HEURISTIC and RANDOM arms cross-check the flat
draw-then-reject expensive gate (`expensive_accept()` at the top of
each pick's retry loop -- draws `!ONE_IN(EXPENSIVE_ADAPTIVE_FLOOR)`
per EXPENSIVE candidate) against a closed-form coin-then-draw pool
selector that lives on top of the cost-partitioned active pools laid
down in Phase 0 (`shm->active_cheap*[]` / `active_expensive*[]` +
`nr_active_cheap` / `nr_active_exp`).

### Cost-pool selector shape (coin-then-draw)

    p_exp   = n_exp   / (n_cheap * R + n_exp)
    p_cheap = n_cheap * R / (n_cheap * R + n_exp)

with `R = EXPENSIVE_ADAPTIVE_FLOOR` (1000, the static accept
denominator the flat picker uses for EXPENSIVE candidates today).  The
closed form yields the same accept-fraction across the two pools as
the flat draw-then-reject picker in EXPECTATION -- see the
cost-pool-oneshot-selector spec section 4.1 for the algebra.  On each
pick this row observes `n_cheap` / `n_exp` under the same arch table
the live picker chose, computes the per-pool expected fractions, and
accumulates them into `cost_pool_selector_shadow_*` counters (see
`include/stats.h`).  It does NOT draw a shadow pick -- only the
closed-form expected values are summed, so the shadow accounting
consumes ZERO `rnd_u32()` calls and cannot perturb the live pick
stream even when SHADOW_ONLY is engaged.  The live pick itself STAYS
the flat draw-then-reject shape (flat `active_syscalls[]` uniform draw
+ `expensive_accept` early-out); the pools are watched, not driven,
until COMBINED lands the coin-then-draw wire-up in a follow-up commit.

### Mode ramp

- **OFF** -- default, byte-identical to today.  The HEURISTIC and
  RANDOM arms skip the shadow observer entirely; no atomic loads of
  the per-pool counters fire, no divide is computed, no
  `cost_pool_selector_shadow_*` counter is bumped, no per-syscall
  bookkeeping is touched.  Under a fixed-seed `--dry-run` the pick
  stream and every counter are bit-for-bit identical to a build before
  this row.
- **SHADOW_ONLY** -- the observer engages at the top of the HEURISTIC
  and RANDOM arms (after `choose_syscall_table` but before the retry
  loop's live `rnd_modulo_u32` draw): read `n_cheap` / `n_exp` for the
  chosen arch under RELAXED, compute the analytical expected per-pool
  fractions, and bump the
  `cost_pool_selector_shadow_picks` / `shadow_expensive_ppm_sum`
  aggregate under RELAXED.  Live selection stays the flat
  draw-then-reject -- the observer never returns a value, never gates
  any accept, never consumes RNG.  Read the
  `(shadow_expensive_ppm_sum / (shadow_picks * 1e6))` analytical
  fraction against the
  `(live_expensive_picks / (live_expensive_picks + live_cheap_picks))`
  actual-accept fraction to confirm the section 4.1 identity holds
  empirically on a real run before promoting COMBINED.
- **COMBINED** -- reserved.  The enum value exists so the
  coin-then-draw wire-up (dispatch by the shadow `p_exp` coin, then a
  uniform draw from the elected pool) can land in a follow-up commit
  without renumbering the enum, but THIS COMMIT does NOT implement the
  live selector -- selecting combined today behaves identically to
  shadow-only (observer accumulates, live pick stays flat
  draw-then-reject).  Mirrors the OFF / SHADOW_ONLY / COMBINED ramp
  discipline the sibling `frontier_saturation_cooldown_mode` /
  `frontier_group_antilock_mode` rows use.

Param-settable from `--cost-pool-selector=off|shadow-only|combined`.

## Context-pool mode -- regular_suppressed instrumentation

Path-A "regular_suppressed" shadow instrumentation for the picker.
Sibling of `cost_pool_selector_mode`; layered on the same OFF /
SHADOW_ONLY / COMBINED ramp discipline the other picker observers use,
and gated at the outer edge so OFF is byte-identical to a build before
this row.

The axis this observes is orthogonal to cost: cost partitions on a
static EXPENSIVE bit, context partitions on empirical per-syscall
EPERM behaviour -- run-persistent `per_syscall_errno` +
`per_syscall_edges` data classifies a syscall as `regular_suppressed`
(proven regular-dead) so the shadow row projects how many finalised
picks a live Path-A suppression would remove from the regular cost
pools.  The classifier is data-gated, NOT a curated exception list --
membership is derived from the kcov counters at the pick site
(magnitude floor + `success == 0` + `edges == 0` + EPERM rate
>= threshold); a newly-productive syscall stops being classified
`regular_suppressed` on its own without any manual map edit.  Shared
spare-lane predicate (`frontier_spare_lane_decide`) is consumed at the
site so a syscall the K-window ring says is recently productive is
spared from the `would_skip` attribution even if its lifetime EPERM
rate is still high -- keeps the shadow projection honest against
transient recovery.

### Mode ramp

- **OFF** -- default, byte-identical to today.  Single RELAXED mode
  load short-circuits before any `kcov_shm` access, any per-syscall
  counter load, or any shadow counter bump.  Fixed-seed `--dry-run`
  pick streams are bit-for-bit identical to a build before this row.
- **SHADOW_ONLY** -- compute the classifier at the pick-finalise site
  (once per accepted pick, matched to the
  `cost_pool_selector_live_note` cadence so the
  `(context_regular_suppressed_would_skip /
  context_regular_suppressed_candidates)` ratio reads directly off the
  finalised pick population).  Bumps the
  `context_regular_suppressed_*` shadow counters; selection stays
  byte-identical -- no goto-retry is gated on the classifier, no live
  suppression fires.
- **COMBINED** -- reserved.  The enum value exists so a future commit
  that wires the live regular-pool removal
  (`deactivate_syscall_locked` on the `regular_suppressed` subset) can
  land without renumbering the enum, but THIS BUILD treats combined
  identically to shadow-only -- classifier evaluates and counters
  bump, no live pool change happens.  The switchover is a separate,
  gated step after SHADOW_ONLY validates the classifier against a real
  run per the `needs-root-pool-userns-axis-2026-06-27` §5 Phase 2 A/B
  ramp.

Param-settable from `--context-pool=off|shadow-only|combined`.

## Strategy selection reason

Why `select_next_strategy()` returned the arm it returned.  Stamped on
each window so the rotation site can tell a policy-chosen arm from an
intervention forced over the top of the picker, and so end-of-run
stats can report the two cohorts separately.

- `SR_NORMAL_UCB` -- UCB1 scored this arm highest among eligible arms.
- `SR_ROUND_ROBIN` -- `PICKER_ROUND_ROBIN` cycled to this arm (or the
  "everything ineligible" fallback ran).
- `SR_COLD_START` -- UCB1 picked this arm because it had zero pulls
  and the score formula is undefined until each arm has been observed
  at least once.
- `SR_PLATEAU_FORCE` -- The plateau-intervention orchestrator overrode
  the picker and forced this arm because `kcov` reports edge discovery
  is stalled.  Windows with this reason are NOT fed back into the UCB
  learner: a forced-RANDOM intervention window is structurally
  different from a policy-chosen RANDOM window (every arm was stalled
  when this one ran), so mixing them into
  `bandit_pulls[]`/`bandit_reward_calls[]` contaminates the reward
  signal.

## Random-rescue classifier

When the orchestrator forces `STRATEGY_RANDOM` during a coverage
plateau (`SR_PLATEAU_FORCE`) and that forced window's RANDOM picks
produce new edges, those edges are evidence that some structured bias
the normal picker imposes was filtering out a productive path.  The
classifier inspects the `(predecessor, syscall)` pair against the
existing heuristic / cmp-hint state and assigns the rescue to the
narrowest category that explains why the structured path missed it.

Counts accumulate in `shm->random_rescue_class_count[]` across all
intervention windows and the dominant class feeds back into the
orchestrator (see `select_next_strategy`) as a hint for which targeted
intervention to run next instead of plain RANDOM.

Classes are checked in order; the FIRST matching class wins, so the
enum ordering encodes priority.  Classes whose detection requires
infrastructure that does not yet exist (persona / namespace
attribution, per-call fd-producer tracking) are defined so the
orchestrator's bias dispatch covers the full surface even though the
classifier will not credit a rescue to them today; they sit as
placeholder buckets the future infrastructure can fill in without an
enum reorder.

Currently dispatched classes (those the classifier actively attributes
today): `RRC_COLD_SKIP`, `RRC_CMP_DERIVED`, and the `RRC_UNKNOWN`
catch-all.

- `RRC_COLD_SKIP` -- `rec->nr` would have been skipped under
  `STRATEGY_HEURISTIC`'s `kcov` cold-skip gate
  (`kcov_syscall_cold_skip_pct >= 50`).
- `RRC_UNUSUAL_FD_PRODUCER` -- placeholder for per-call fd-source
  tracking; today never selected by the classifier.
- `RRC_WRONG_TYPE_FD` -- placeholder; typed-fd substitution gave a
  wrong-class fd that worked.  Today never selected.
- `RRC_CMP_DERIVED` -- this syscall has a non-empty `cmp_hints` pool,
  so `generate-args.c`'s 1-in-16 `cmp_hints_try_get` path may have
  injected a learned constant that carried the call past a kernel
  validation check the structured pickers were not pushing through.
- `RRC_PERSONA_GATED` -- placeholder for namespace/cgroup/childop
  persona attribution; persona infrastructure does not exist yet,
  never selected today.
- `RRC_UNKNOWN` -- rescue did not match any structured class.

## Plateau intervention mode

During a coverage plateau the orchestrator forces an arm over the top
of the bandit; without further structure that arm has been plain
`STRATEGY_RANDOM` (`PIM_UNIFORM_RANDOM`) or, once the random-rescue
classifier has accumulated evidence, a class-amplified replay
(`PIM_RRC_BIASED`, dispatched through `dominant_rescue_class`).  Both
modes leave one rescue avenue untouched: the bandit's learned priors
over per-syscall pick rate.  A learner that has converged on a handful
of "winning" syscalls keeps replaying them across the intervention
even when those wins are stale -- the priors themselves are part of
why the fleet is at plateau.

`PIM_ANTI_PRIOR` is the complement: `STRATEGY_RANDOM` with a per-call
acceptance gate that INVERTS the learned per-syscall call-count
distribution.  Syscalls the bandit has been suppressing (low
per-syscall call count) get full acceptance; syscalls the bandit has
been over-picking (high count) get rejected at up to `MAX_BOOST^-2` of
baseline acceptance.  The inversion is capped so a syscall stuck at
`calls=0` (genuinely broken in this kernel, or simply never picked
before the plateau started) cannot 100x dominate the intervention.

`PIM_COVERAGE_FRONTIER` unconditionally selects
`STRATEGY_COVERAGE_FRONTIER` for the window so the frontier-weighted
picker runs regardless of what the bandit would have selected.  The
bandit cannot pull the frontier arm during a plateau (the intervention
layer short-circuits the bandit entirely while `plateau_active` is
set), so without this mode the frontier picker is structurally
unreachable for the duration of every plateau -- exactly the windows
where chasing near-coverage edges is most likely to break the stall.
Layered alongside the other intervention modes so the per-mode A/B
comparison includes the frontier picker on the same rotation cadence
as anti-prior and RRC-biased.

The orchestrator round-robins among the four modes at each rotation
boundary while the plateau is active, so the per-mode rescue yield is
directly comparable: each mode runs the same number of windows over
the lifetime of any plateau long enough for the rotation to cycle.
Anti-prior and RRC-biased modes are designed as complements --
anti-prior biases AWAY from the learned distribution, RRC-biased
biases TOWARD a specific failure class -- and both layer over the
UNIFORM_RANDOM baseline that makes the A/B shape interpretable.

- `PIM_UNIFORM_RANDOM` -- `STRATEGY_RANDOM` with no per-call bias.
  The historical pre-classifier intervention shape; kept as a rotation
  slot to anchor the comparison.
- `PIM_ANTI_PRIOR` -- `STRATEGY_RANDOM` with the inverted-weight
  accept gate active (see `plateau_anti_prior_accept()`).
- `PIM_RRC_BIASED` -- dispatch via `dominant_rescue_class()` +
  `amplified_intervention_arm()` -- HEURISTIC or COVERAGE_FRONTIER
  replay biased by the random-rescue classifier's dominant class, or
  plain RANDOM when no class dominates.
- `PIM_COVERAGE_FRONTIER` -- `STRATEGY_COVERAGE_FRONTIER`
  unconditionally, so the frontier-weighted picker is reachable during
  plateaus the bandit would otherwise keep off the arm.

## Bandit reward shape -- edge-count blend

`CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL` is the reward weight for the
CMP-novelty secondary signal, expressed as the integer reciprocal of
0.25.  Each novel CMP constant contributes
`1/CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL` to the bandit's per-window
reward, so PC edges (weight 1.0) remain the dominant signal and CMP
variety acts as a tiebreaker / decay-resistor for arms whose PC growth
has plateaued but whose comparison surface is still mutating.
Hard-coded today; future work may expose this via CLI.

`EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL` is the reward weight for
the edge-count secondary signal.  `pc_edge_count` (real bucket-edge
bits flipped per window) is typically an order of magnitude larger
than `pc_edge_calls` (calls with >=1 edge), so the raw delta would
dwarf the call-count headline signal.  A reciprocal of 8 folds a 1/8
secondary weight onto the call-count reward, matching the "PC-edge
stays dominant, secondary signal tie-breaks" shape the CMP-novelty
term already uses.  Hard-coded for the initial shadow ramp; the
operator-facing `bandit_edge_count_reward_added` counter plus the
parallel `bandit_reward_pc_edge_count[]` series lets the value be
re-tuned against real runs before COMBINED is defaulted on.

### Blended-reward mode (bandit_reward_edge_count_mode)

Wires the `bandit_reward_pc_edge_count[]` real-bucket-count series --
collected today alongside `bandit_reward_calls[]` but never consumed
by `ucb1_score` -- into the learner-facing reward total via the
secondary edge-count term.  Shadow-first ramp mirrors
`kcov_transition_reward_mode`:

- **OFF** -- default, byte-identical to today.  The edge-count term
  is not computed, no shadow counter bumps, and the bandit reward
  total remains `pc_edge_calls + cmp_term` (`+ trans_term` when the
  transition reward is combined).  Fixed-seed runs reproduce the
  pre-knob per-window reward exactly.
- **SHADOW_ONLY** -- compute the
  `edge_count_term = pc_edge_count / EDGE_COUNT_BANDIT_REWARD_WEIGHT_RECIPROCAL`
  and bump the diagnostic `bandit_edge_count_reward_added` counter on
  every window where the term is non-zero, but DO NOT fold the term
  into the total the ucb1 learner sees.  Selection stays
  byte-identical to OFF; the counter surfaces how often COMBINED would
  have moved the reward, and the operator can compare its rate against
  `bandit_cmp_reward_added` / the frequency the CMP secondary term
  fires today.
- **COMBINED** -- fold the `edge_count_term` into the bandit reward
  total.  `bandit_reward_calls[]` then reflects
  call-count + weighted CMP novelty + weighted edge-count on every
  window.  Rollout path: promote to COMBINED only after the SHADOW
  counter shows the term firing on a meaningful fraction of windows on
  a representative run.

`SR_PLATEAU_FORCE` windows already short-circuit the learner-facing
update path in `bandit_record_pull()`; the edge-count term goes
through the same gate, so a forced-intervention window's edge yield is
not folded into the learner even under COMBINED.

## Plateau hypothesis machinery

On the rising-edge transition into `plateau_active` the orchestrator
captures a snapshot of every counter the rule evaluator will need to
classify WHY discovery has stalled.  A later periodic tick computes
the current snapshot, derives the per-counter delta vs the entry
snapshot, and feeds the delta into the rule evaluator.  The
evaluator's result is published to `shm->plateau_current_hypothesis`
so per-call consumer gates can read it.

### Consumer contract

Per-call gates -- the strategy-selection rotation in
`select_next_strategy` is a flat round-robin and does NOT pin a mode
based on the hypothesis.

- `PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT` --
  `minicorpus.c minicorpus_maybe_replay()` doubles the corpus replay
  rate (25% -> 50%) and narrows the slot picker to the `K_RECENT`
  newest entries to favour freshly-admitted CMP-source material.
- `PLATEAU_HYPOTHESIS_CHILDOP_DOMINANT` -- `child.c pick_op_type()`
  raises the non-dedicated-child alt-op burst threshold from 5% to
  25% so the alt-op channel that's out-discovering generic syscalls
  gets a proportionate share.
- `PLATEAU_HYPOTHESIS_REMOTE_DOMINANT`,
  `PLATEAU_HYPOTHESIS_FRONTIER_COLD`,
  `PLATEAU_HYPOTHESIS_SINGLE_GROUP_DOMINANT` -- no consumer today,
  diagnostics only.  Their fire counters surface in the periodic stats
  line and the end-of-run dump so the operator can see the cumulative
  distribution; wiring a consumer is a design decision, not a
  follow-on cleanup.

### Storage

`struct plateau_window_snapshot` lives in shm-free memory -- the entry
snapshot is parent-private (only the parent walks the plateau detector
+ rule check) and ride-along snapshots are stack-local on the tick
path.

### Field origins

All sourced from existing counters; no new wiring.

- `pc_edges` (edges) -- `kcov_shm->coverage.edges_found`.  Headline coverage
  signal, the same counter the plateau detector itself watches the
  rate of.
- `cmp_unique` (records) -- `kcov_shm->hints_flat.cmp_hints_unique_inserts`.
  Counts CMP records that survived bloom + pool dedup and changed pool
  state -- the right denominator for "how much unique CMP signal is
  the kernel still emitting" while `pc_edges` has flattened.
- `bandit_edges`, `explorer_edges` (calls) --
  `shm->stats.{bandit,explorer}_pool_edges_discovered`.  Despite the
  `_edges_` name these are CALL counts: bumped by 1 per syscall pick
  that surfaced one or more new edges (`random-syscall.c`), not by
  the number of edges that call surfaced.  Excludes alt-op childops.
- `childop_edges_total` (edges) -- sum of
  `shm->stats.childop_edges_discovered[]` across `enum child_op_type`.
  EDGE count -- bumped by `(edges_after - edges_before)` per alt-op
  invocation in the post-call `have_kcov` block.  Kept for the stats
  panels; do NOT compare directly against `bandit/explorer_edges`,
  those are call counts (see `childop_calls_total` below).
- `childop_calls_total` (calls) -- sum of
  `shm->stats.childop_calls_with_edges[]` across
  `enum child_op_type`.  CALL count -- bumped by 1 per alt-op
  invocation that surfaced at least one new edge.  This is the
  apples-to-apples comparator for `bandit_edges` / `explorer_edges`
  in the plateau classifier's Rule 2 ratio.
- `remote_calls`, `total_calls` --
  `kcov_shm->coverage.{remote,total}_calls`.  `KCOV_REMOTE_ENABLE` share of
  the dispatch mix; inline = total - remote.
- `frontier_picks` -- `shm->stats.frontier_strategy_picks`.  Calls
  that went through the coverage-frontier roulette wheel.
- `frontier_pulls` -- `shm->bandit_pulls[STRATEGY_COVERAGE_FRONTIER] +
  shm->stats.frontier_intervention_pulls`.  Windows in which the
  bandit (or the cold-start / round-robin path) selected the CFV arm,
  PLUS plateau-intervention rotations that resolved to the CFV arm
  via `PIM_COVERAGE_FRONTIER` or the `RRC_CMP_DERIVED` dispatch
  through `amplified_intervention_arm()`.  The fold-in keeps the
  frontier-cold rule honest while `plateau_active` is set: the bandit
  counter is structurally frozen during plateaus (the intervention
  layer short-circuits the bandit), so without the intervention term
  the rule could never fire on a plateau the intervention layer was
  already addressing.  Paired with `frontier_picks`: when the picker
  pulled CFV but the weighted-accept gate inside it rejected every
  candidate, pulls advances while picks stays at 0.  The
  frontier-cold rule uses the delta against this pair to distinguish
  "picker never tried CFV" (uninformative) from "picker tried CFV and
  every candidate was rejected" (frontier really is cold).
- `frontier_live_picks`, `frontier_silent_picks` -- accept-regime
  split of `frontier_picks`.  Sourced from
  `shm->stats.frontier_{live,silent}_picks`; sum equals
  `frontier_picks`.  Surfaced as deltas via
  `plateau_snapshot_delta` so the per-tick plateau hypothesis line
  can show which regime owned the window's picks -- "silent
  dominates" inside a plateau means the cold-weight fallback is doing
  the steering rather than the K-window ring.
- `group_edges[NR_GROUPS]` -- per-syscall-group sum of
  `kcov_shm->per_syscall.per_syscall_edges[]`, grouped by
  `syscalls[nr].entry->group`.  Maps the call-count new-edge signal
  onto the `GROUP_*` axis the classifier needs for the
  single-group-dominant rule.

Captured at entry; deltas read at every tick.  The saturating-subtract
invariant enforced by `plateau_snapshot_delta` is the load-bearing
piece: it stays as a one-line invariant next to the function
declaration in the header.

### Hypothesis classifier

Each `enum plateau_hypothesis` value names ONE hypothesis about why
discovery has stalled.  The orchestrator publishes the matched value
to `shm->plateau_current_hypothesis` on every tick and bumps a
per-hypothesis fire counter on every transition into a non-NONE class.
Per-call consumer gates in `child.c` and `minicorpus.c` read the
published value and apply targeted biases for the two hypotheses that
have consumers today (see the consumer contract above); unconsumed
hypotheses surface only via the fire-count distribution and remain
diagnostics-only.

Conservative thresholds throughout: each rule needs evidence that
would not show up in a healthy or short-lived plateau window.  See
`strategy_plateau_hypothesis_check()` in `strategy.c` for the exact
comparisons.

Rules are checked in enum order and the FIRST match wins, so the
ordering encodes precedence -- `CMP_RISING_PC_FLAT` is the most
specific (we can see CMP signal still arriving while PC has gone cold)
and `SINGLE_GROUP_DOMINANT` is the most general (one group accounting
for `>70%` of edges is informative but compatible with several
finer-grained explanations).
