#pragma once

/* KCOV mode enums and companion constants split out of kcov-types.h.
 * Each mode's comment lives next to its enum (the consumer of the mode).
 * Included from kcov-types.h so any file that includes kcov-types.h keeps
 * seeing these types transparently. */

/* 8-bucket errno classification used by per_syscall_errno[] below.
 * Bucket layout is part of the dump_stats() output contract; keep
 * the order stable so the column headers in stats.c match. */
enum errno_bucket {
	ERRNO_BUCKET_SUCCESS = 0,	/* rec->retval != -1UL */
	ERRNO_BUCKET_EFAULT  = 1,
	ERRNO_BUCKET_EINVAL  = 2,
	ERRNO_BUCKET_ENOSYS  = 3,
	ERRNO_BUCKET_EPERM   = 4,
	ERRNO_BUCKET_EBADF   = 5,
	ERRNO_BUCKET_EAGAIN  = 6,
	ERRNO_BUCKET_OTHER   = 7,
	ERRNO_BUCKET_NR      = 8,
};

/* Shadow transition-coverage mode (--kcov-transition-coverage).
 *
 *   OFF    - skip the transition hash inside kcov_collect.  The map
 *            and counters stay zero; nothing else in Trinity reads
 *            them today, so this is purely a "don't pay the per-PC
 *            cost" knob.
 *   SHADOW - default.  Hash consecutive canonical PCs into the
 *            transition map and bump the transition_* counters in
 *            parallel with the existing PC bitmap update.  Stats dump
 *            surfaces the top transition-yielding syscalls alongside
 *            the existing PC top-N so the two signals can be compared
 *            side-by-side; transition deltas do NOT feed
 *            bandit_record_pull(), frontier_record_new_edge(), the
 *            plateau detector, or any other steering consumer yet.
 *            Promotion to a reward source is gated on the shadow
 *            signal proving out first. */
enum kcov_transition_coverage_mode {
	KCOV_TRANSITION_COVERAGE_OFF = 0,
	KCOV_TRANSITION_COVERAGE_SHADOW = 1,
};

extern enum kcov_transition_coverage_mode kcov_transition_coverage_mode;

/* Transition-edge reward mode (--kcov-transition-reward).  Promotes the
 * shadow transition-coverage signal (see kcov_transition_coverage_mode
 * above) from observability-only into an active reward input for the
 * scheduler.  The coverage mode must be SHADOW for any of the reward
 * modes below to do work; if coverage is OFF the per-syscall transition
 * counters never bump and every reward path below sees a zero delta.
 *
 *   OFF          - skip the reward path entirely.  Per-strategy
 *                  transition attribution counters stay zero, the
 *                  frontier-cold-weight blend drops back to its
 *                  pre-transition formula (PC-edge + bucket-bits +
 *                  distinct-PCs only), and bandit_record_pull adds no
 *                  transition term.
 *   SHADOW_ONLY  - compute the transition-reward terms and bump the
 *                  per-strategy attribution counters in shm->stats so
 *                  the operator can read the divergence, but DO NOT
 *                  change live picker behaviour: frontier_cold_weight()
 *                  returns the pre-transition weight, bandit_record_
 *                  pull() drops the transition term from the reward
 *                  total, and the frontier-edge ring is bumped only by
 *                  the PC-edge hook.  Selecting this mode leaves
 *                  selection byte-identical to the pre-knob baseline;
 *                  kept as a rollback path now that COMBINED is the
 *                  default.
 *   COMBINED     - default.  Feed the capped transition reward into
 *                  live selection: frontier_cold_weight() returns the
 *                  transition-blended weight, bandit_record_pull()
 *                  folds the transition window delta into the per-arm
 *                  reward total, and the transition-discovery hook
 *                  bumps the frontier-edge ring alongside the PC-edge
 *                  hook so syscalls that produce only transitions
 *                  (no fresh PC bits) still earn frontier credit.
 *
 * Remote-mode constraint: remote-mode kcov traces merge coverage
 * copied from remote contexts into the same buffer; the ordering of
 * the merged PCs is not verified to preserve transition adjacency, so
 * a remote-mode transition record carries a weaker signal than a
 * local-mode one.  Even under COMBINED, remote-mode calls do NOT bump
 * any of the live-reward inputs (the per-syscall _real_local counter,
 * the per-strategy attribution counters, or the transition-discovery
 * frontier hook) so the live reward sees local-mode transitions only.
 * The existing per_syscall_transition_edges[_real] counters keep
 * including remote contributions for the unchanged stats-dump top-N.
 */
enum kcov_transition_reward_mode {
	KCOV_TRANSITION_REWARD_OFF = 0,
	KCOV_TRANSITION_REWARD_SHADOW_ONLY = 1,
	KCOV_TRANSITION_REWARD_COMBINED = 2,
};

extern enum kcov_transition_reward_mode kcov_transition_reward_mode;

/* --expensive-adaptive: adaptive accept-rate mode for the EXPENSIVE
 * early-out gate in random-syscall.c.
 *
 * The static gate is `syscall_is_expensive(nr, do32) && !ONE_IN(1000)`:
 * EXPENSIVE-flagged syscalls take a fixed 999/1000 reject, so fleet
 * wall-cost stays bounded but the gate cannot scale the rate based on
 * what the syscall is producing.  This mode flag selects how the
 * per-syscall productivity signal (per_syscall_edges /
 * per_syscall_calls, plus the warm-loaded _prior arrays and a
 * total_calls -- last_edge_at gap decay re-using the kcov_syscall_cold_
 * skip_pct shape) influences the live accept denominator.
 *
 *   OFF          - default.  Byte-identical to the static expression:
 *                  no kcov_shm reads, no adaptive math, the single
 *                  ONE_IN(1000) RNG draw fires in the same conditions
 *                  as the original `&&` short-circuit -- the pick
 *                  stream is preserved bit-for-bit for a given seed.
 *   SHADOW_ONLY  - compute the adaptive denominator (cost path active)
 *                  but the LIVE accept still draws ONE_IN(1000); pick
 *                  stream stays identical to OFF.  Placeholder for the
 *                  follow-up row that adds shadow A/B counters.
 *   COMBINED     - the adaptive denominator drives the live accept
 *                  (ONE_IN(n_adaptive)).  Only mode that diverges from
 *                  OFF.  The decay back toward the floor when a
 *                  syscall stops producing edges is load-bearing: the
 *                  floor caps wall-cost, so an adaptive grant MUST
 *                  decay once productivity stops.
 *
 * Degrade-safe: helper falls back to the static 1/1000 rate when
 * kcov_shm is unavailable, same fallback shape kcov_syscall_cold_skip_
 * pct / frontier_cold_weight already take. */
enum expensive_adaptive_mode {
	EXPENSIVE_ADAPTIVE_MODE_OFF = 0,
	EXPENSIVE_ADAPTIVE_MODE_SHADOW_ONLY = 1,
	EXPENSIVE_ADAPTIVE_MODE_COMBINED = 2,
};

extern enum expensive_adaptive_mode expensive_adaptive_mode;

/* Per-window transition delta divided by this reciprocal before being
 * folded into the bandit's per-arm reward total in bandit_record_pull
 * under COMBINED mode.  Matches the shape (and starting value) of
 * CMP_BANDIT_REWARD_WEIGHT_RECIPROCAL: a 0.25 secondary weight against
 * the PC-edge-call primary signal.  Tunable once the COMBINED arm has
 * soaked enough A/B data to bias the choice. */
#define TRANSITION_BANDIT_REWARD_WEIGHT_RECIPROCAL 4

/* Per-call clamp on how many transition slots a single trace can
 * contribute to the per-strategy reward counters.  A pathological
 * trace that opens a brand-new control-flow region can flip thousands
 * of transition slots in one call; without this clamp such a trace
 * would monopolize the per-strategy delta the bandit reads as reward,
 * letting one window's worth of luck dominate the learner.  The raw
 * per_syscall_transition_edges_real counter stays uncapped (it is the
 * stats-dump observability signal), and the frontier_cold_weight blend
 * uses ilog2() as its per-call clamp -- this constant only gates the
 * per-strategy bandit-reward path. */
#define TRANSITION_PER_CALL_REWARD_CAP 64UL

/* Transition-discovery sibling of frontier_record_new_edge() defined
 * in strategy.c.  Declared here (rather than alongside frontier_
 * record_new_edge in include/strategy.h) because the function exists
 * solely to feed the transition-reward path: its only caller is the
 * COMBINED-mode branch in random-syscall.c, and gating the prototype
 * to the same header that defines kcov_transition_reward_mode keeps
 * "who is allowed to call this" co-located with "what makes calling
 * this meaningful".  See the function body for the contract. */
void frontier_record_transition_edge(unsigned int nr);

/* KCOV trace modes */
#define KCOV_TRACE_PC  0
#define KCOV_TRACE_CMP 1

/*
 * Per-child KCOV mode.  The kernel rejects a second KCOV_ENABLE on the
 * same task with -EBUSY (the one-`t->kcov`-per-task rule in kernel/kcov.c),
 * so PC and CMP collection cannot run simultaneously inside a single
 * child.  Each child picks one mode at init and keeps it for its
 * lifetime; the fleet-wide PC/CMP signal split comes from the population
 * mix of children, not from per-call mode toggling.
 */
enum kcov_child_mode {
	KCOV_MODE_PC = 0,
	KCOV_MODE_CMP,
};

/*
 * Reciprocal probability that a child runs in CMP-only mode.  CMP records
 * feed the constant-comparison hint pool, which helps the fuzzer break
 * plateaus by unblocking comparison-gated kernel branches; PC coverage is
 * the load-bearing signal for everything else (bandit reward attribution,
 * edge-discovery rate, cold-syscall skipping).
 * Biased toward PC mode so the high-frequency signal isn't starved; retune
 * after A/B if cmp_records throughput is the bottleneck.
 */
#define KCOV_CMP_CHILD_RECIPROCAL 4   /* 1-in-4 children run CMP-only */

/* Selector for kcov_cmp_diag_format() — keeps stats.c's two-line split
 * (init vs runtime sites) while still allowing main/loop.c to fold all six
 * sites into a single one-line summary. */
enum kcov_cmp_diag_part {
	KCOV_CMP_DIAG_INIT,	/* init_open, init_init_trace, init_mmap */
	KCOV_CMP_DIAG_RUNTIME,	/* init_enable, init_disable, runtime_enable */
	KCOV_CMP_DIAG_ALL,
};

/* observability: the two generate-args.c callsites that pull a value via
 * prop_ring_try_get() are partitioned into fixed buckets so the
 * per-callsite propagation-injection split is visible alongside the flat
 * propagation_injected scalar.  Ordering is pinned (the slot index is the
 * bucket id) -- append-only.  Distinct from enum cmp_hint_callsite (in
 * cmp_hints.h): that one buckets cmp_hints_try_get() consumers (kernel
 * KCOV_TRACE_CMP value source), this one buckets prop_ring_try_get()
 * consumers (trinity-observed syscall-return value source). */
enum prop_injected_callsite {
	PROP_INJECTED_CALLSITE_ARG_OP = 0,
	PROP_INJECTED_CALLSITE_ARG_UNDEFINED,
	PROP_INJECTED_CALLSITE_NR,
};

/* Probe-class buckets for the cmp_hyp_probe_class_hist[] census at the
 * tail of struct kcov_shared.  Every entry above the SHADOW block below
 * corresponds one-for-one with a branch cmp_hyp_derive_value() ACTUALLY
 * emits a value through today; keep those in lock-step with the switch.
 * The set deliberately excludes the false-return rejects (hi < lo,
 * default kind) which emit no value.  The BOUNDARY_* classes are the
 * neighbourhood ladder the CMP_HYP_BOUNDARY arm walks -- inequality-
 * gate-friendly probes RANGE deliberately refuses to emit because the
 * value-keyed credit walk can only reach interior members.
 *
 * SHADOW-only classes are appended at the tail below _SINGLE_BIT's
 * live siblings.  They are reserved as dedicated bucket ids so a
 * future live promotion of a shadow-measured lane can flip on without
 * shifting the histogram indices consumers already read; today they
 * are never assigned to `cls` inside the derive switch, so their
 * cmp_hyp_probe_class_hist[] slots stay at zero and the dedicated
 * shadow counters at the tail of struct kcov_shared carry the
 * would-fire / would-win signal instead. */
enum cmp_hyp_probe_class {
	CMP_HYP_PROBE_CLASS_EXACT_EXEMPLAR,
	CMP_HYP_PROBE_CLASS_ENUM_EXEMPLAR,
	CMP_HYP_PROBE_CLASS_ENUM_LO,
	CMP_HYP_PROBE_CLASS_ENUM_HI,
	CMP_HYP_PROBE_CLASS_BITMASK_SINGLE_BIT,
	CMP_HYP_PROBE_CLASS_EXEMPLAR_FALLBACK,
	CMP_HYP_PROBE_CLASS_RANGE_LO,
	CMP_HYP_PROBE_CLASS_RANGE_HI,
	CMP_HYP_PROBE_CLASS_RANGE_MIDPOINT,
	CMP_HYP_PROBE_CLASS_BOUNDARY_MINUS1,
	CMP_HYP_PROBE_CLASS_BOUNDARY_PLUS1,
	CMP_HYP_PROBE_CLASS_BOUNDARY_EXACT,
	CMP_HYP_PROBE_CLASS_BOUNDARY_SWEEP,
	/* SHADOW-only bitmask combination classes.  Extend the existing
	 * BITMASK single-bit lane in cmp_hyp_derive_value() with combo
	 * probes: FULL_OR is the OR of all single-bit observations at
	 * (nr, cmp_ip, width) (targets `(flags & A) && (flags & B)`
	 * gates single-bit probing structurally cannot reach);
	 * ANDNOT_TOGGLE flips one disallowed bit at a time within the
	 * complement of the observed-bits set at the same site (targets
	 * `old & ~c` allow-mask checks).  No branch in the derive switch
	 * emits either value today; the dedicated shadow counters below
	 * carry the coverage-headroom signal. */
	CMP_HYP_PROBE_CLASS_BITMASK_FULL_OR,
	CMP_HYP_PROBE_CLASS_BITMASK_ANDNOT_TOGGLE,
	CMP_HYP_PROBE_CLASS_NR,
};
