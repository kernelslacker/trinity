# Picker heuristics tuning options

Companion to `main/params/help.c`, `random_syscall/pick-common.c`,
`random_syscall/pick-heuristic.c`, `random_syscall/pick-random.c`.
These options are shadow-first tuning knobs for the HEURISTIC and
RANDOM picker arms.  The `--help` output carries only a one-line
contract per option; the rationale, the classifier the observer
computes, and the shadow-vs-live promotion criteria live here.

Every three-mode option accepts the same spelling: `off`,
`shadow-only`, `combined`.  `off` short-circuits before any
per-syscall counter is loaded and is bit-for-bit identical to a build
without the row.  `shadow-only` runs the observer and bumps
observability counters; selection stays byte-identical to `off`.
`combined` is where the observer gates the live picker; several
options ship it as **RESERVED** (identical to `shadow-only` in this
build) so the enum value can land before the divergence is wired.

## --context-pool

Path-A regular_suppressed context-axis shadow observer for the
HEURISTIC and RANDOM picker arms.  At pick-finalise, alongside the
sibling `cost_pool_selector_live_note` attribution, the observer
classifies the accepted syscall as `regular_suppressed` when its
run-persistent kcov counters say it is regular-dead:

    lifetime per_syscall_calls_total >= CONTEXT_REGULAR_SUPPRESSED_CMIN &&
    per_syscall_errno[SUCCESS] == 0 &&
    per_syscall_edges_total == 0 &&
    per_syscall_errno[EPERM] / calls >= CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT

and bumps `context_regular_suppressed_*` shadow counters split by the
shared `frontier_spare_lane_decide` spare cascade
(`windowed-edges` / `arggen` / `objproducer` / `none-of-the-above`
== `would_skip`).

- `off`: skip the classifier entirely; no kcov_shm access, no
  per-syscall counter loads, no spare-lane evaluation, no counter
  bumps.  Fixed-seed `--dry-run` pick streams are bit-for-bit
  identical to a build before this row.
- `shadow-only`: classify + bump.  Selection stays byte-identical;
  no goto-retry or accept-gate is influenced, no live regular-pool
  deactivation fires.
- `combined` (RESERVED): identical to `shadow-only` in this build; a
  follow-up wires the live regular-pool removal
  (`deactivate_syscall_locked` on the regular_suppressed subset).

Validate the per-syscall `would_skip` distribution against the
measured EPERM hogs (`fchown` / `chown` / `lchown` / `fchownat` plus
the cred family as seen at uid 1026) (expected high) and against
syscalls with unprivileged regular value (expected ~0) under
`shadow-only` before tuning `CMIN` / `EPERM_PCT` or wiring the
`combined` live suppression.

See `include/strategy.h` enum `context_pool_mode` for the mode
contract and `CONTEXT_REGULAR_SUPPRESSED_CMIN` /
`CONTEXT_REGULAR_SUPPRESSED_EPERM_PCT` for the classifier thresholds.

## --cost-pool-selector

Cost-pool one-shot selector shadow observer for the HEURISTIC and
RANDOM picker arms.  At the top of each pick, after
`choose_syscall_table` but before the retry loop's live
`rnd_modulo_u32` draw, the observer reads the arch-specific
`nr_active_cheap` / `nr_active_exp` pair under RELAXED, computes the
closed-form per-pool expected fractions from the section 4.1
identity:

    p_exp = n_exp / (n_cheap * R + n_exp)  with R = EXPENSIVE_ADAPTIVE_FLOOR = 1000

and accumulates them into the
`cost_pool_selector_shadow_picks` / `cost_pool_selector_shadow_expensive_ppm_sum`
aggregate.  NO shadow pick is drawn -- the observer consumes ZERO
`rnd_u32()` calls so the pick stream stays identical to `off` for a
given seed.

The parallel
`cost_pool_selector_live_cheap_picks` / `cost_pool_selector_live_expensive_picks`
accepted-pick counters bump regardless of this flag so the analytical
(shadow) fraction can be validated empirically against the live
draw-then-reject fraction on any run.

- `off`: skip the observer entirely; no per-pool counter loads, no
  divide, no `cost_pool_selector_shadow_*` counter bump.
- `shadow-only`: observer accumulates.
- `combined` (RESERVED): identical to `shadow-only` in this build; a
  follow-up wires the live coin-then-draw dispatch on top of the
  `shm->active_cheap*[]` / `active_expensive*[]` pools.

Validate:

    (shadow_expensive_ppm_sum / (shadow_picks * 1e6))

matches:

    (live_expensive_picks / (live_expensive_picks + live_cheap_picks))

under `shadow-only` before wiring `combined`.

## --expensive-adaptive

Adaptive accept-rate mode for the EXPENSIVE early-out gate in
`random_syscall/pick-common.c`.  The prior gate hardcodes
`syscall_is_expensive && !ONE_IN(1000)`; this row conditions the
denominator on per-syscall productivity so a productive EXPENSIVE
syscall earns a faster accept and a stale one decays back to the
1/1000 floor.

- `off`: gate is byte-identical to the prior expression -- no
  kcov_shm reads, no adaptive math, single `ONE_IN(1000)` RNG draw
  fires only on EXPENSIVE-flagged candidates so the pick stream is
  preserved bit-for-bit for a given seed.
- `shadow-only`: compute the adaptive denominator from
  `(per_syscall_edges + warm-loaded _prior) / per_syscall_calls` with
  a `total_calls - last_edge_at` gap decay back toward the floor; the
  LIVE accept still draws `ONE_IN(1000)` so the pick stream stays
  identical to `off`.  Placeholder for the follow-up row that wires
  shadow A/B counters.
- `combined`: the adaptive denominator drives the live accept -- a
  productive EXPENSIVE syscall earns up to a 1/50 rate, a
  once-productive-now-stale slot decays back to the 1/1000 floor over
  `EXPENSIVE_ADAPTIVE_DECAY_STEPS` contiguous `KCOV_COLD_THRESHOLD`-sized
  gap steps.

Degrade-safe: kcov-less / bad-index callers fall back to the static
1/1000 floor.

## --cred-throttle

Credential-syscall throttle.  When a credential class
(`setregid` / `setreuid` / `setresuid` / `setresgid` / `setgid` /
`setuid` / `setfsuid` / `setfsgid` / `setgroups`) has accumulated
`>=64` attempts with zero successes and `EPERM+EINVAL` dominating
`>=90%` of returns, downweight the class by rejecting `31/32` of
subsequent picks.

Flag off keeps the picker distribution byte-identical to a build
without this row; the per-class observability counters are bumped
regardless of this flag so operators can grep the throttle
opportunity size before flipping live.  Default off.

## --corpus-save-errno-grad-live

Errno-gradient corpus save trigger (`CORPUS_SAVE_REASON_ERRNO`).
When a syscall returns a non-EFAULT errno bucket for the first time
this run, admit its args to the per-syscall ring so a future replay
can chase the newly-visited failure branch.

Flag off keeps the corpus admission distribution byte-identical to a
build without this trigger; the `errno_grad_save_would_save` shadow
counter is bumped regardless of this flag so the would-be-save volume
is measurable before flipping live.  Default off.
