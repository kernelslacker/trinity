# --cmp-frontier design notes

Companion to `include/cmp-frontier.h`.  The header keeps the enum,
concise per-mode contracts, and load-bearing invariants; this
document holds the multi-paragraph rationale explaining *why* the arm
exists, what plateau it targets, and how the signal scale was picked.

## Why a CMP-weighted alternate arm

Today the silent-regime weight returned by `frontier_cold_weight()`
is a PC-coverage-led inverse-productivity signal -- a syscall that
has produced no `per_syscall_edges` relative to its
`per_syscall_calls` ranks high.  Under the coverage-wall plateau
classified as `PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT` (CMP-pool
inserts continuing to rise while `edges_found` is flat) the PC-led
ranking has nothing new to chase even though CMP activity says a
productive frontier still exists.

This row adds an alternate weight derived from the existing
per-syscall CMP signal counters --
`kcov_shm->per_syscall_cmp.per_syscall_cmp_inserts[nr]` (durable CMP pool inserts)
and `kcov_shm->childop_cmp.childop_cmp_pool_inserts[nr]` (childop CMP pool
inserts) -- so a syscall whose CMP-side activity is high but whose
PC-edge growth is flat ranks high under the new arm.  The two
counters are the same ones the `dump_stats()` "Top syscalls by CMP
unique inserts" sibling block already uses to surface this exact
pattern; the picker reads them straight, no parallel sampler is
introduced.

On top of that insert-volume base the helper adds a conversion-rate
bonus derived from `per_syscall_cmp_injected` (denominator) and
`per_syscall_cmp_hint_pc_wins + per_syscall_cmp_hint_transition_wins`
(numerator -- PC-edge wins plus typed-hyp transition wins summed so
a transition-rich syscall does not read as flat just because PC
edges have plateaued).  The bonus is gated on a sample-size floor
(`CMP_FRONTIER_MIN_INJECTED`, 32) so a `1/1 = 100%` noise spike
cannot dominate ranking against syscalls with thousands of
injections; a syscall with `0%` conversion (or below the floor)
sees `conv_bonus = 0` and ranks on inserts alone -- the historical
inserts-only behaviour is the degrade-safe fallback.  This lifts a
proven converter out of its insert-volume tier without letting it
monopolise the frontier.

## Mode ladder in detail

`OFF` is the A/B baseline: the silent-regime accept gate skips the
CMP arm entirely -- no mode-load past the early return, no
CMP-counter load, no arithmetic, no weight change.  Fixed-seed
dry-run is byte-identical to a build before the row; the mode load
itself consumes no RNG.

`SHADOW_ONLY` computes the CMP-weighted alternate weight and the
would-route decision, then bumps the shadow counters in stats so the
would-be divergence is observable on a single run.  The live returned
weight stays at the PC-led value, so picks are identical to `OFF` for
a given seed.

`COMBINED` is the only mode that diverges from `OFF`: the silent-
regime accept gate replaces the PC-led weight with the CMP-weighted
alternate weight on picks where the plateau classifier currently
reads `PLATEAU_HYPOTHESIS_CMP_RISING_PC_FLAT` -- the "rank the silent
regime by CMP-derived signal instead" contract.  Off-plateau picks
retain the PC-led weight.  A syscall with no CMP activity sees its
weight drop to 0 under the swap, which the `(w + 1) / (SCALE + 1)`
accept floor in the silent gate keeps reachable rather than
unreachable.

## Degrade-safe posture

`kcov_shm == NULL` or `nr >= MAX_NR_SYSCALL` bails the helper to zero
weight before any CMP counter is touched, matching the
`FRONTIER_COLD_SCALE` fallback `frontier_cold_weight()` and the rest
of the picker file take.  The plateau hypothesis load is `RELAXED`
-- a torn sample that misses the `CMP_RISING_PC_FLAT` value degrades
the `COMBINED` arm to "no route" for that pick rather than wrapping
selection.

## CMP_FRONTIER_SIGNAL_SCALE derivation

Scale on the `ilog2`-clamped CMP-signal sum.  Each of the two
per-syscall counters contributes `ilog2(count + 1)`, in `[0, 63]`;
a typical observed pair tops out around `(10, 10)` so the sum sits
in the `~0..20` range under heavy CMP activity.  Multiplying by 8
spreads that range across most of `[0, FRONTIER_COLD_SCALE]` (256)
so the `(w + 1) / (SCALE + 1)` accept floor in the silent gate sees
a usable spread instead of compressing every active syscall to the
same near-cap weight.  Saturated at `FRONTIER_COLD_SCALE` in the
helper.

The conversion-rate bonus described in "Why a CMP-weighted
alternate arm" is folded in additively before the `SIGNAL_SCALE`
multiply: `signal = ilog2(cmp_inserts + 1) + ilog2(childop_inserts
+ 1) + conv_bonus`, where `conv_bonus = ilog2(1 + rate_milli *
CMP_FRONTIER_CONVERSION_SCALE / 1000)` and `rate_milli` is
wins-per-1000-injections.  `CMP_FRONTIER_CONVERSION_SCALE` (256)
caps the bonus at roughly `ilog2(257) = 8` for a 100%-converting
syscall, which sits in the same magnitude band as a saturated
inserts-side term and roughly doubles the typical `8..12` base
signal for a proven converter.  Below `CMP_FRONTIER_MIN_INJECTED`
(32) injections, or at zero wins, `conv_bonus = 0` and the signal
reduces to the inserts-only sum -- degrade-safe against small-N
noise spikes and against syscalls the CMP-hint pipeline has yet to
touch.  The saturating clamp at `FRONTIER_COLD_SCALE` applies to
the final `signal * SIGNAL_SCALE`, so the bonus never pushes past
the same cap the inserts-only weight already respected.
