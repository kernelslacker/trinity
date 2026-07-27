# Frontier picker tuning options

Companion to `main/params/help.c` and `include/strategy.h`.  These
options are shadow-first tuning knobs for the coverage-frontier
picker's silent- and live-regime accept paths.  The `--help` output
carries only a one-line contract per option; the full rationale, the
predicate the classifier evaluates, and the validation checklist
before ramping past `shadow-only` live here.

Every mode listed accepts the same three-way spelling: `off`,
`shadow-only`, `combined`.  `off` short-circuits before any
per-syscall counter is loaded and is bit-for-bit identical to a build
without the row.  `shadow-only` runs the predicate and bumps
observability counters but leaves selection byte-identical to `off`.
`combined` is where the classifier gates the live picker; several
options ship it as **RESERVED** (identical to `shadow-only` in this
build) so the enum value can land before the divergence is wired.

## --frontier-live-cooldown-mode

LIVE-regime cooldown discriminator for the coverage-frontier picker's
miss-attribution path.  When a syscall's miss streak crosses
`FRONTIER_LIVE_MISS_COOLDOWN`, the existing rotation-loop halving
kicks in; the discriminator asks whether the syscall still has a
spare lane (windowed edges, distinct CMP, first-success, ret_objtype)
that would earn back its slot before the halving takes effect.  Gated
by the `FRONTIER_LIVE_COOL_CMIN` low-live floor so the discriminator
does not fire on cold syscalls that have no per-syscall history yet.

- `off`: skip the discriminator entirely; the frontier_live_cool_*
  shadow counters stay zero.
- `shadow-only`: compute the discriminator inside the streak branch
  and bump frontier_live_cool_* counters.  Selection is byte-identical
  to `off`; the existing `frontier_live_would_skip` projection keeps
  running so the (live_cool_would_skip / live_would_skip) ratio reads
  the over-cool the discriminator would remove.
- `combined` (RESERVED): identical to `shadow-only` in this build; a
  follow-up wires the rotation-loop halving + per-syscall reject gated
  on the discriminator.

Validate the per-syscall would-skip distribution against
`gettid` / `sched_get_priority_max` (expected high) and
`bpf` / `io_uring_setup` / `openat` / `io_setup` / `futex` /
`setxattrat` (expected ~0) under `shadow-only` before tuning C_min or
wiring the `combined` divergence.  Independent of the existing
boolean `--frontier-live-cooldown` (which gates the rotation-loop
halving alone).

## --frontier-barren-demote

Floored-barren sub-floor demote predicate for the coverage-frontier
picker's silent-regime accept site.  Targeted debugging knob:
default-off; only enable for a run measuring the vetted zero-arg
getter cohort.  The vetted predicate isolates the skeleton
syscall -- no args, no producer, no mutator, low reach, past the
call floor, zero edges lifetime and windowed -- and is what keeps
object-producers, state-mutators, and heuristic-arm spike sources out
of the demote set.  `num_args == 0` alone is necessary but NOT
sufficient.

Full predicate:

    num_args == 0 &&
    ret_objtype == OBJ_NONE &&
    sanitise == NULL &&
    reach <= FRONTIER_BARREN_MAX_REACH &&
    calls > FRONTIER_BARREN_C_MIN &&
    lifetime_edges == 0 &&
    windowed_edges == 0

- `off`: skip the predicate entirely; selection and shadow counters
  both stay zero.
- `shadow-only`: evaluate the predicate inside the silent-regime
  accept block and bump `frontier_barren_*` shadow counters.
  Selection is byte-identical to `off`; no goto-retry is gated.
- `combined` (RESERVED): identical to `shadow-only` in this build; a
  follow-up wires the live sub-floor divergence swapping the silent
  accept denominator to `(FRONTIER_COLD_SCALE * FRONTIER_BARREN_DEMOTE_MULT + 1)`.

Validate the per-syscall would-skip distribution reads the pure
zero-arg getter cohort before considering the `combined` ramp.

## --frontier-saturation-cooldown

Saturation-cooldown predicate for the coverage-frontier picker's
silent-regime accept site.  Computes a corrected windowed-edge
plateau plus the `FRONTIER_SATCOOL_CMIN` magnitude gate plus a
distinct-CMP / first-success / ret_objtype spare-lane predicate; the
combined shape isolates the saturated-productive syscall whose recent
edge yield has flatlined and whose alternate signal lanes are empty.

- `off`: skip the predicate entirely; selection and shadow counters
  both stay zero.
- `shadow-only`: compute the predicate inside the silent-regime
  accept block and bump `frontier_satcool_*` shadow counters.
  Selection is byte-identical to `off`.
- `combined` (RESERVED): identical to `shadow-only` in this build; a
  follow-up wires the live reject.

Validate the per-syscall would-skip distribution against
`syncfs` / `sendfile` / `semget` / `writev` (expected high) and
`removexattrat` / `futex` / `io_uring_setup` / `bpf` (expected ~0)
under `shadow-only` before tuning C_min or wiring the `combined`
reject.

## --frontier-group-antilock

Group-bias anti-lock-in damper for the heuristic-arm picker's
`group_bias` gate.  Runs a dispatch-step per-child bookkeeping of the
streak, watermark, and fd-warm markers, then evaluates a
`pin_stale && !pin_warm` release predicate at the group_bias gate
site.  Targets the case where the heuristic arm has been pinned to a
group for a long stretch without lifting new edges from that group's
fd-warm cohort -- the pin is stale, the group is not warming
anything, and the pin should be released so another group gets a
turn.

- `off`: skip the windowed-pin predicate entirely; per-child streak /
  watermark / fd-warm bookkeeping AND shadow counters all stay
  dormant.
- `shadow-only`: run the bookkeeping and evaluate the release
  predicate; bump `frontier_frseq_*` shadow counters.  Selection
  stays byte-identical.
- `combined` (RESERVED): identical to `shadow-only` in this build; a
  follow-up wires the live pin release.

Validate the per-syscall would-skip distribution against
`rseq_slice_yield` / `getpgrp` / `sched_yield` (expected high) and
`socket` / `sendto` / `openat` (expected ~0), and the per-group
distribution against `GROUP_PROCESS` (=5, expected high) vs
`GROUP_NET` / `GROUP_VFS` (expected ~0) under `shadow-only` before
tuning `MIN_STREAK` / `COV_WINDOW` or wiring the `combined` release.
No-op unless `--group-bias` is also set; the F-RSEQ-5 caveat in the
design note applies.
