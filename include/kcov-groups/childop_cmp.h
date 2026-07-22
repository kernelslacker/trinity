#pragma once

/* Sub-struct of struct kcov_shared, embedded as .childop_cmp.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_childop_cmp {
unsigned long childop_cmp_brackets_opened;
unsigned long childop_cmp_brackets_skipped_pc_mode;
unsigned long childop_cmp_brackets_skipped_incapable;
unsigned long childop_cmp_brackets_skipped_nested;
unsigned long childop_cmp_brackets_skipped_inactive;
unsigned long childop_cmp_record_cap_hits;
unsigned long childop_cmp_insert_cap_hits;
unsigned long childop_cmp_syscalls_sampled[MAX_NR_SYSCALL];
unsigned long childop_cmp_records_collected[MAX_NR_SYSCALL];
unsigned long childop_cmp_pool_inserts[MAX_NR_SYSCALL];
unsigned long childop_cmp_pool_evicts[MAX_NR_SYSCALL];
unsigned long childop_cmp_trace_truncated[MAX_NR_SYSCALL];
unsigned long childop_cmp_window_contaminated[MAX_NR_SYSCALL];
/* Per-childop syscall-sample census, indexed by enum child_op_type.
 * Lets the operator see which childop is dominating the lane before
 * the §3.2 noisy-syscall skip-list would need tuning.  Same
 * KCOV_CHILDOP_NR_MAX bound the PC-side childop_kcov_* arrays use. */
unsigned long childop_cmp_syscalls_sampled_per_op[KCOV_CHILDOP_NR_MAX];
};
