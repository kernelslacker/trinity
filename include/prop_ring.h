#pragma once

#include <stdbool.h>

#include "syscall.h"

struct childdata;

/*
 * Per-child ring of small-integer return values from recently completed
 * syscalls.  Mirrors the live_fds machinery (include/child.h) but for the
 * non-fd small-int case: cookies, key serials, queue ids, signal numbers
 * etc. -- values trinity received as a syscall return and could feed back
 * as input to a later call to compose a multi-step protocol chain.
 *
 * Capture in handle_syscall_ret() after register_returned_fd(); inject
 * with low probability in gen_undefined_arg().  Single-writer (owning
 * child) / single-reader (same child during arg generation), so no
 * atomics are needed.  Power-of-2 size keeps the head wrap a mask.
 */
#define CHILD_PROP_RING_SIZE 32

struct prop_slot {
	unsigned long	value;		/* returned scalar */
	unsigned long	captured_at;	/* child->op_nr snapshot at capture */
	unsigned int	src_nr;		/* syscall index that produced value */
	bool		do32bit;	/* table the src_nr indexes */
	bool		valid;		/* false in zero-init slots */
};

struct child_prop_ring {
	struct prop_slot slots[CHILD_PROP_RING_SIZE];
	unsigned int head;
};

void prop_ring_push(struct childdata *child,
		    const struct syscallentry *entry,
		    const struct syscallrecord *rec);

/*
 * Try to pull a recent return value out of CHILD's ring for injection
 * as an input arg to the syscall described by REC.  On success returns
 * true, stores the value in *OUT, and (when BOOSTED_OUT is non-NULL)
 * stamps *BOOSTED_OUT with whether the call was accepted via the
 * edgepair-top-quartile 2x boost (true) or the Phase 1 baseline path
 * (false).  Lets the caller bump
 * propagation_edgepair_boosted_injected for the boost-attributed
 * subset of propagation_injected.
 */
bool prop_ring_try_get(struct childdata *child,
		       const struct syscallrecord *rec,
		       unsigned long *out,
		       bool *boosted_out);

/*
 * Recompute the edgepair top-quartile threshold from the published
 * mirror and write it into kcov_shm->prop_edgepair_topq_threshold.
 * Called by the CAS-winner in maybe_rotate_strategy once per strategy
 * window so the hot-path comparison in prop_ring_try_get stays a
 * single relaxed atomic load.  No-op when KCOV is unavailable or the
 * edgepair mirror is not yet populated; in that case the threshold
 * keeps its prior value (ULONG_MAX on cold start, the last computed
 * cutoff on subsequent windows) so the boost gate fails closed.
 */
void prop_ring_recompute_edgepair_topq(void);
