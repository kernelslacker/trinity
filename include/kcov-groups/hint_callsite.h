#pragma once

/* Sub-struct of struct kcov_shared, embedded as .hint_callsite.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_hint_callsite {
unsigned long cmp_hint_callsite_injected[CMP_HINT_CALLSITE_NR];

/* PC-mode outcome partition by callsite -- WIN numerator per
 * callsite bucket.  Sibling of cmp_hint_callsite_injected[] above
 * (which is the per-callsite denominator: how many pulls were
 * committed to a produced arg) and of cmp_hint_pc_wins_by_pool[]
 * (which partitions the same PC-mode win credit by pool-kind).
 * Bumped from cmp_hints_feedback_credit_pc() once per stashed entry
 * whose credit lands on a win, using the callsite the stash was
 * stamped with at consume time in cmp_hints_stash_consumed().
 * Existing splits: callsite-INJECTED-only + pool-WIN-only; this
 * closes the callsite-WIN hole so a typed-eligible baseline
 * (ARG_STRUCT_SIZE + ARG_RANGE) can be projected out of the raw
 * pool wins rather than compared against the aggregate.  Stash
 * entries with an unset / out-of-range callsite (field-pool pulls
 * from cmp_hints_field_try_get, which have no argtype-handler
 * callsite) are not attributed here, so sum(_by_callsite) can be
 * less than the flat cmp_hint_wins / cmp_hint_misses. */
unsigned long cmp_hint_callsite_pc_wins[CMP_HINT_CALLSITE_NR];
unsigned long cmp_hint_callsite_misses[CMP_HINT_CALLSITE_NR];
};
