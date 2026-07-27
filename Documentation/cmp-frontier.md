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

## --cmp-shared-tier

Fleet-wide shared `cmp_ip` tier rollout mode.  The shared tier is a
cross-syscall pool of CMP IPs seen at least once anywhere in the
fleet; it exists so a syscall's durable per-nr pool can be warm-seeded
at cold-miss time by values another syscall has already learned.  An
entry-path filter (`distinct_nr_count > CMP_SHARED_TIER_ENTRY_PATH_NR_MAX`)
excludes IPs that fire under too many syscalls to be a useful
warm-start seed -- those are shared kernel entry frames, not
syscall-specific.

- `off`: both the collect-side insert and the get-side shadow probe
  short-circuit BEFORE any shared-tier shm access; every
  `cmp_shared_tier_*` counter stays at zero, and a fixed-seed
  `--dry-run` pick stream is bit-for-bit identical to a build before
  the shared tier landed.
- `shadow`: populate the tier at warm-load and on every fresh
  `pool_add_locked` success, and on every `cmp_hints_try_get_ex`
  cold-miss return -- durable per-nr pool empty on the requested
  `(nr, do32)` and the recent-tier pre-pass did not serve -- bump
  `cmp_shared_tier_shadow_warmstart_eligible` when the tier has at
  least one non-entry-path IP available to seed from.  The probe
  does NOT read or return a tier value, does NOT consume RNG, and
  does NOT change what `try_get` returns.
  `cmp_shared_tier_shadow_dedup_supplied` captures the cross-nr
  redundant-learn opportunity size.
- `combined`: LIVE cold-miss serve on top of the shadow probe.  On
  every `cmp_hints_try_get_ex` cold miss -- durable per-nr pool empty
  on the requested `(nr, do32)` AND the recent-tier pre-pass returned
  MISS -- the shadow probe fires as under `shadow` AND
  `cmp_shared_tier_try_serve_cold_miss` consumes RNG
  (`ONE_IN(CMP_SHARED_TIER_SERVE_DICE)` budget gate plus an
  `rnd_modulo_u32` random-start bucket walk) to elect an occupied
  non-entry-path shared-tier bucket and return that value as the
  `try_get` hit, altering the live pick.  The stash sets
  `served_from_shared=1` so the credit drain routes the PC outcome to
  the shared-tier lane only and a shared-served value NEVER becomes
  native pool evidence.

NOT an inert / RESERVED control tier -- an operator running
`combined` as an A/B control against `off` or `shadow` will see live
arg mutation on cold misses.

Validate the
`(shadow_dedup_supplied / cmp_hints_unique_inserts)` cross-nr
redundancy rate and the
`(shadow_warmstart_eligible / cold-miss population)` opportunity
size under `shadow`, and use the shared-tier lane wins/misses
counters under `combined` to gauge whether served values earn their
consumption.

## --childop-cmp-harvest

Producer side of the per-childop CMP pool.  Open a per-childop
`KCOV_TRACE_CMP` bracket on CMP-mode children at the `child.c`
childop dispatch gate; childop syscalls routed through
`trinity_cmp_syscall` harvest their CMP operands into the QUARANTINED
`childop_recent_pools[nr][do32]` lane (non-persisted; does NOT evict
the durable per-syscall cmp pool).

- `off`: the bracket is never opened; `trinity_cmp_syscall` is a
  no-op wrapper around `trinity_raw_syscall`; every
  `childop_cmp_*` shadow counter stays at zero -- the childop
  dispatch surface is byte-identical to a build without this knob.
- `on`: the bracket opens on every CMP-mode child whose dispatch
  reaches the existing `op_uses_outer_bracket` gate; honour the §3.2
  all-routed invariant on any childop migrated to
  `trinity_cmp_syscall`.

Per-childop migration to the wrapper is a separate per-op step
earned by the conversion-chain metrics; the OFF default ships the
harvest path behaviour-neutral.  Default off.

## --childop-cmp-consume

Consumer side of the per-childop CMP pool.  Enable the SHADOW
consume-side resolver `childop_cmp_value()` at childop field sites
(rxrpc pilot: `kver` / `security_index` / `ticket_length` / `toklen`
/ `tktlen` / `sec_ix` / `enctype` in
`childops/net/rxrpc-key-install.c`).

- `off`: `childop_cmp_value` returns the caller's rng fallback
  verbatim before any `cmp_hints_try_get_ex` probe; every
  `childop_cmp_consume_*` counter in `kcov_shm` stays at zero and
  the field-site pick stream is byte-for-byte identical to a build
  without this knob.
- `on`: the resolver probes the durable per-nr pool via
  `cmp_hints_try_get_ex` and bumps `_would_pick` / `_would_miss` /
  `_would_value_differs` on the outcome, but STILL returns the
  caller's rng fallback -- no arg is changed and no downstream
  behaviour differs.

Independent of `--childop-cmp-harvest`: the two knobs gate
producer-side and consumer-side of the same childop CMP pool, and
the pool is shared, so `consume` can bump `_would_pick` against
warm-started / non-childop entries even with `harvest` OFF.

The conversion-chain counters (`_candidate_accepted` /
`_arg_changed` / `_outcome_changed` / `_new_cov`) ship declared but
never bumped in this build; C3 / C4 slices fill them in once the
shadow readout justifies live consume.  Default off.
