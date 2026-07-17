#ifndef _TRINITY_STATS_SUBSYS_ERRNO_GRADIENT_H
#define _TRINITY_STATS_SUBSYS_ERRNO_GRADIENT_H

#include "syscall.h"	/* MAX_NR_SYSCALL */

/* Shadow errno-class gradient (measurement only -- no fuzzer
 * behaviour change).  Hypothesis: arg-gen crossing kernel
 * validators (errno class moving toward success on a given
 * syscall) precedes hitting new PC edges.  This block instruments
 * that hypothesis as a SHADOW so a future live phase can be gated
 * on its signal.  No selection / admission / scoring / corpus path
 * consumes any field here -- the only effect of these writes is
 * the counter values rendered by the shutdown stats dump.
 *
 * Gradient classes (3 ordered slots; low -> high "progress into
 * the kernel"):
 *   0  hard reject / other -- EINVAL, ENOSYS, EBADF, EFAULT,
 *      ENOTTY, AND any errno not listed below.  The catchall lives
 *      in class 0 so a previously-unseen errno cannot synthesise a
 *      spurious crossing into class 1.
 *   1  permission/state reject -- EPERM, EACCES, EAGAIN, EBUSY,
 *      EOPNOTSUPP.
 *   2  success -- rec->retval != -1UL (errno is don't-care).
 *
 * Bumped from syscall_ret_post_phase() under the existing per-
 * syscall errno-bucket histogram gate (state == AFTER, kcov_shm
 * != NULL, call < MAX_NR_SYSCALL), so the same filter that keeps
 * grandchild-killed and pre-validation paths out of the bucket
 * histogram keeps them out of this gradient too.  RELAXED load +
 * compare-exchange on the per-syscall last-class slot; on a
 * strictly-greater observation the aggregate scalars below are
 * bumped under RELAXED add-fetch.  Equal / downward transitions
 * leave the slot untouched and bump no counter.  Racing producer
 * bumps are tolerated -- worst case is a one-pick over/under-count
 * of the aggregates, never a perturbation of live selection.
 *
 * All four start at zero on parent boot; warm-start does not
 * persist stats counters. */
struct errno_gradient_stats {
	/* last_class[nr]
	 *      Last observed class for syscall nr (values in {0,1,2};
	 *      slot is zero-initialised so the first observation of any
	 *      class > 0 produces a crossing, matching the "first deeper
	 *      bucket per syscall" intent).  Per-syscall stash -- NOT
	 *      rendered, INTERNAL to the gradient predicate.  Updated via
	 *      compare-exchange so two children racing the same nr can
	 *      both publish but only the strictly-greater observation wins
	 *      and bumps. */
	unsigned long last_class[MAX_NR_SYSCALL];

	/* crossings
	 *      Aggregate scalar -- total upward gradient crossings across
	 *      all syscalls.  Equals to_permstate + to_success modulo the
	 *      brief race between the total bump and the per-target-class
	 *      bump.  Doubles as the STAT_CATEGORY gate so a run with zero
	 *      crossings emits nothing in the text dump. */
	unsigned long crossings;

	/* to_permstate
	 *      Subset of crossings: crossings that landed in class 1 (the
	 *      permission/state-reject tier). */
	unsigned long to_permstate;

	/* to_success
	 *      Subset of crossings: crossings that landed in class 2
	 *      (success).  The headline "actually reached the kernel's
	 *      success path on a syscall that previously only rejected"
	 *      signal. */
	unsigned long to_success;
};

#endif /* _TRINITY_STATS_SUBSYS_ERRNO_GRADIENT_H */
