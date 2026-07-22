#pragma once

/* Sub-struct of struct kcov_shared, embedded as .cmp_nonconst.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_cmp_nonconst {
unsigned long cmp_nonconst_arg1_unique;      /* rec_args has exactly one slot == arg1 */
unsigned long cmp_nonconst_arg2_unique;      /* rec_args has exactly one slot == arg2 */
unsigned long cmp_nonconst_both_match;       /* both operands appear in rec_args (>=1 each) */
unsigned long cmp_nonconst_would_attribute;  /* exactly one side uniquely ours, other absent */
unsigned long cmp_nonconst_measured;         /* addressable denominator: non-const records
					      * where rec_num_args>0 (the population the
					      * shadow measurement actually evaluated).
					      * reject_nonconst is strictly larger -- it
					      * counts every non-const drop incl. child==
					      * NULL / redqueen disabled / in_reexec /
					      * dispatch_args invalid / reexec_pending
					      * full-at-entry, all cases where rec_num_args
					      * is 0 and the per-slot loop never runs. */
};
