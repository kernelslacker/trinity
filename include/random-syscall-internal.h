#ifndef _TRINITY_RANDOM_SYSCALL_INTERNAL_H
#define _TRINITY_RANDOM_SYSCALL_INTERNAL_H

/*
 * Internal interface shared by the random-syscall cluster files under
 * random_syscall/ (pick-common.c, pickers.c, chain-subst.c,
 * strategy-accounting.c, dispatch.c).
 *
 * Public entry points (random_syscall, random_syscall_step,
 * random_syscall_step_biased, replay_syscall_step,
 * set_syscall_nr_random, compute_numeric_substitute_mask,
 * choose_syscall_table) live in include/child.h and include/syscall.h.
 * Everything declared here is cross-cluster private glue that the
 * follow-up cluster carves add as they move code out.  Not a public
 * header: only files under random_syscall/ are expected to include it.
 */

#include <stdbool.h>

struct childdata;
struct syscallrecord;
struct syscallentry;
struct kcov_pc_result;

/* pick-common.c -- table selection and validation helpers, shared by
 * the three picker arms in pickers.c.  choose_syscall_table is public
 * via include/syscall.h; the rest are cluster-private. */
void note_validation_success(unsigned int syscallnr, bool do32);
void note_validation_failure(unsigned int syscallnr, bool do32);
bool expensive_accept(unsigned int nr, bool do32);
void cost_pool_selector_shadow_note(bool do32);
void cost_pool_selector_live_note(unsigned int nr, bool do32);
bool syscall_in_group(unsigned int nr, bool do32, unsigned int target_group);

/* pickers.c -- top-level picker dispatch, called from dispatch_step
 * in dispatch.c.  set_syscall_nr_random is public via
 * include/syscall.h; the other picker arms
 * (set_syscall_nr_heuristic, set_syscall_nr_coverage_frontier) and
 * their helpers (frontier_cold_weight, cmp_frontier_weight,
 * ilog2_ul) are file-scope static inside pickers.c. */
bool set_syscall_nr(struct syscallrecord *rec, struct childdata *child);

#endif /* _TRINITY_RANDOM_SYSCALL_INTERNAL_H */
