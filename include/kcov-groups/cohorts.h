#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cohorts.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_ab_cohorts {
/* A/B cohort split + per-arm baseline-injection fire counts +
 * per-call divergence counter for the cmp-hint baseline inject denom
 * A/B (Arm A = 1-in-16, Arm B = 1-in-12).  cmp_inject_arm_{a,b}_
 * children is bumped once per child in init_child_runtime_config so
 * the operator can normalise the per-arm fire rate against the
 * realised population split (the ONE_IN(2) stamp has fleet-scale
 * variance and a small fleet can land lopsided).  cmp_inject_arm_b_
 * baseline_fires counts the baseline-callsite ONE_IN that fired on an
 * Arm B child; the matching Arm A count is the existing
 * cmp_hint_callsite_injected[] baseline buckets minus this delta, but
 * a flat sibling counter is provided here too for read-ergonomics.
 * cmp_inject_denom_diverged is bumped once per baseline-callsite call
 * on an Arm B child when the same uniform sample would have produced
 * a different fire/skip decision for Arm A than for Arm B (the
 * helper rolls one sample in [0, lcm(16,12)) and tests both denoms).
 * Bumping only on Arm B children leaves Arm A's per-call RNG
 * sequence byte-identical to before this row -- the divergence
 * counter is a lower bound on the per-call decision delta but
 * preserves the A-arm-purity invariant the A/B row demands. */
unsigned int  cmp_inject_arm_a_children;
unsigned int  cmp_inject_arm_b_children;
unsigned long cmp_inject_arm_a_baseline_fires;
unsigned long cmp_inject_arm_b_baseline_fires;
unsigned long cmp_inject_denom_diverged;
/* A/B cohort split + per-arm fire count for the prop_ring injection at
 * handle_arg_op's ARG_OP callsite.  prop_ring_argop_arm_{a,b}_children
 * is bumped once per child in init_child_runtime_config so the operator
 * can normalise the Arm B fire rate against the realised population
 * split (the ONE_IN(2) stamp has fleet-scale variance and a small fleet
 * can land lopsided).  prop_ring_argop_arm_b_fires counts the Arm B
 * pulls that returned a recent kernel-handed-back scalar and committed
 * it as the ARG_OP command code; Arm A never pulls so the symmetric
 * arm_a counter does not exist by design.  Fires are also reflected in
 * the existing flat propagation_injected counter so the operator can
 * read the combined prop_ring contribution across both consumer sites
 * (gen_undefined_arg + handle_arg_op) without re-summing. */
unsigned int  prop_ring_argop_arm_a_children;
unsigned int  prop_ring_argop_arm_b_children;
unsigned long prop_ring_argop_arm_b_fires;
/* A/B cohort split + per-kind consume counters for the typed
 * prop_ring consumer rows at the gen_arg_* callsites
 * (prop_ring_typed_arm_b).  prop_ring_typed_arm_{a,b}_children
 * is bumped once per child in init_child_runtime_config so the
 * operator can normalise the per-kind fire rate against the
 * realised population split (the ONE_IN(2) stamp has fleet-scale
 * variance and a small fleet can land lopsided).  Arm A never
 * pulls at these callsites so the symmetric arm_a fire counter
 * does not exist by design.
 *
 * prop_ring_kind_consumed[K] counts Arm B same-kind pulls that
 * returned a recent kernel-handed-back scalar tagged K from the
 * ring; slot 0 (SCALAR_UNTYPED) stays at zero by construction
 * since the typed entry point rejects it on the caller side.
 * prop_ring_kind_escape_fires counts the chaos-escape lane
 * (a typed callsite that took an any-kind slot via the 1-in-N
 * escape hatch), kept out of the per-kind buckets so the kind-
 * discipline signal is not polluted by escape-hatch traffic.
 * Sum across non-zero buckets + escape_fires is the total Arm B
 * typed-pull commit count; it is NOT mirrored into
 * propagation_injected because that counter is the
 * gen_undefined_arg / handle_arg_op (untyped consumer) total
 * and the typed sites are a separate channel by design. */
unsigned int  prop_ring_typed_arm_a_children;
unsigned int  prop_ring_typed_arm_b_children;
unsigned long prop_ring_kind_consumed[SCALAR_NR_KINDS];
unsigned long prop_ring_kind_escape_fires;
/* A/B cohort split for the frontier_cold_weight blend promotion
 * stamp (frontier_blend_arm_b).  frontier_blend_arm_{a,b}_children
 * is bumped once per child in init_child_runtime_config so the
 * operator can normalise the realised population split against the
 * fleet-scale variance of the ONE_IN(2) stamp (a small fleet can
 * land lopsided).  Observation-only -- the counters do not
 * influence the blend weight or the picker; they are the
 * denominator the existing frontier_blend_samples /
 * frontier_blend_new_{lower,higher,equal} totals (in shm->stats,
 * fed from both arms in lock-step) and the live Arm B promotion
 * delta are normalised against. */
unsigned int  frontier_blend_arm_a_children;
unsigned int  frontier_blend_arm_b_children;
/* A/B cohort split for the errno-plateau decay stamp
 * (frontier_errno_decay_arm_b).  frontier_errno_decay_arm_{a,b}_
 * children is bumped once per child in init_child_runtime_config so
 * the operator can normalise the realised population split against
 * the fleet-scale variance of the ONE_IN(2) stamp (a small fleet can
 * land lopsided).  Companion to the frontier_errno_decay_* shm->stats
 * counters bumped at the picker site: the latter measure the would-be
 * and actual demote rates; the cohort split is the denominator the
 * Arm-B-only live reject rate is normalised against. */
unsigned int  frontier_errno_decay_arm_a_children;
unsigned int  frontier_errno_decay_arm_b_children;
/* A/B cohort split for the silent-streak decay stamp
 * (frontier_silent_decay_arm_b).  frontier_silent_decay_arm_{a,b}_
 * children is bumped once per child in init_child_runtime_config so
 * the operator can normalise the realised population split against the
 * fleet-scale variance of the ONE_IN(2) stamp (a small fleet can land
 * lopsided).  Companion to the frontier_silent_decay_live_rejects
 * shm->stats counter bumped at the picker site and to the symmetric
 * frontier_decay_would_skip shadow counter that bumps for both arms:
 * the cohort split is the denominator the Arm-B-only live reject rate
 * is normalised against.  Shape matches frontier_errno_decay_arm_{a,b}
 * _children above so the population-normalisation pattern stays
 * uniform across the A/B rows. */
unsigned int  frontier_silent_decay_arm_a_children;
unsigned int  frontier_silent_decay_arm_b_children;
/* A/B cohort split for the adaptive remote-KCOV mode stamp
 * (remote_adaptive_arm_b).  remote_adaptive_arm_{a,b}_children is
 * bumped once per child in init_child_runtime_config so the operator
 * can normalise the realised population split against the fleet-
 * scale variance of the ONE_IN(2) stamp (a small fleet can land
 * lopsided).  Companion to the remote_adaptive_* shm->stats counters
 * bumped at the dispatch_step site: the latter measure the would-be
 * demote / promote dispositions across BOTH arms in lock-step; the
 * cohort split is the denominator the Arm-B-only live mode flip is
 * normalised against.  Shape matches frontier_blend_arm_{a,b}_
 * children above so the population-normalisation pattern stays
 * uniform across the A/B rows. */
unsigned int  remote_adaptive_arm_a_children;
unsigned int  remote_adaptive_arm_b_children;
};
