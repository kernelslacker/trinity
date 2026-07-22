#pragma once

/* Sub-struct of struct kcov_shared, embedded as .pc_ctx.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_pc_ctx {
unsigned long local_pc_calls[MAX_NR_SYSCALL];
unsigned long remote_pc_calls[MAX_NR_SYSCALL];
unsigned long local_pc_edge_calls[MAX_NR_SYSCALL];
unsigned long remote_pc_edge_calls[MAX_NR_SYSCALL];
unsigned long local_pc_edge_count[MAX_NR_SYSCALL];
unsigned long remote_pc_edge_count[MAX_NR_SYSCALL];
/* Per-childop mirror of the local/remote PC split above, sized
 * to KCOV_CHILDOP_NR_MAX and indexed by op = nr -
 * CHILDOP_KCOV_NR_BASE inside kcov_collect().  Same semantics as
 * the per-syscall arrays; same bump keyed on kc->remote_mode. */
unsigned long childop_local_pc_calls[KCOV_CHILDOP_NR_MAX];
unsigned long childop_remote_pc_calls[KCOV_CHILDOP_NR_MAX];
unsigned long childop_local_pc_edge_calls[KCOV_CHILDOP_NR_MAX];
unsigned long childop_remote_pc_edge_calls[KCOV_CHILDOP_NR_MAX];
unsigned long childop_local_pc_edge_count[KCOV_CHILDOP_NR_MAX];
unsigned long childop_remote_pc_edge_count[KCOV_CHILDOP_NR_MAX];
};
