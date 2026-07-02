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

#endif /* _TRINITY_RANDOM_SYSCALL_INTERNAL_H */
