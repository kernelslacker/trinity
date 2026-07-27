#ifndef _TRINITY_RANDOM_SYSCALL_STRATEGY_ACCOUNTING_INTERNAL_H
#define _TRINITY_RANDOM_SYSCALL_STRATEGY_ACCOUNTING_INTERNAL_H

/*
 * Internal interface for the strategy-window rotation and per-call
 * reward / cohort attribution cluster under random_syscall/.  Carved
 * out of the original strategy-accounting.c so each seam (rotation,
 * remote-adaptive, per-syscall edges, warm-cold reserve, fd+group)
 * lives in its own TU.  Called from dispatch.c on every parent
 * syscall; remote_adaptive_decide is queried from dispatch_step
 * before the raw call to decide whether to publish the remote-
 * adaptive path.
 *
 * Cluster-private glue: only files under random_syscall/ implementing
 * the strategy-accounting subsystem or its direct dispatch caller are
 * expected to include this header.
 */

#include <stdbool.h>

#include "kcov.h"		/* struct kcov_pc_result */
#include "syscall.h"		/* struct syscallentry, struct syscallrecord */
#include "child.h"		/* struct childdata */

void maybe_rotate_strategy(void);
bool remote_adaptive_decide(unsigned int nr,
			    struct syscallentry *entry,
			    bool static_remote);
void account_reexec_ab_cohort(struct childdata *child, unsigned long new_cmp);
void account_per_syscall_new_edges(struct childdata *child,
				   struct syscallrecord *rec,
				   unsigned long new_edge_count);
void account_warm_reserve(struct childdata *child,
			  struct syscallrecord *rec,
			  bool new_edges, unsigned long new_cmp,
			  const struct kcov_pc_result *pcres);
void account_cold_overflow_would_save(struct syscallentry *entry,
				      struct syscallrecord *rec,
				      unsigned long new_cmp);
void account_pc_edge_only(struct childdata *child,
			  struct syscallrecord *rec,
			  unsigned long new_edge_count,
			  unsigned int rescue_cold_skip_pct_before);
void account_transition_reward(struct childdata *child,
			       struct syscallrecord *rec,
			       const struct kcov_pc_result *pcres);
void account_fd_and_group(struct childdata *child,
			  struct syscallentry *entry,
			  struct syscallrecord *rec,
			  bool found_local_coverage);

#endif /* _TRINITY_RANDOM_SYSCALL_STRATEGY_ACCOUNTING_INTERNAL_H */
