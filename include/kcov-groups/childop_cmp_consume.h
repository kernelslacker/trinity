#pragma once

/* Sub-struct of struct kcov_shared, embedded as .childop_cmp_consume.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_childop_cmp_consume {
unsigned long childop_cmp_consume_would_pick[MAX_NR_SYSCALL];
unsigned long childop_cmp_consume_would_miss[MAX_NR_SYSCALL];
unsigned long childop_cmp_consume_would_value_differs[MAX_NR_SYSCALL];
unsigned long childop_cmp_consume_candidate_accepted[MAX_NR_SYSCALL];
unsigned long childop_cmp_consume_arg_changed[MAX_NR_SYSCALL];
unsigned long childop_cmp_consume_outcome_changed[MAX_NR_SYSCALL];
unsigned long childop_cmp_consume_new_cov[MAX_NR_SYSCALL];
};
