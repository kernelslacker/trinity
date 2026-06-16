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
 * Mirror a typed scalar return (currently OBJ_KEY_SERIAL) into the
 * owning child's propagation ring.  Bypasses prop_ring_push()'s
 * OBJ_NONE gate -- the gate exists to keep fd/pid-typed objects from
 * leaking into untyped slots, and is preserved on that path; this
 * variant exists for typed integer cookies whose own registrar has
 * already accepted the value and which can safely be replayed as a
 * scalar input by untyped consumers.  Looks up the owning child via
 * this_child(); no-op if called outside a child context.
 */
void prop_ring_push_scalar(unsigned int nr, long scalar_val);

/*
 * Try to pull a recent return value out of CHILD's ring for injection
 * as an input arg to the syscall described by REC.  On success returns
 * true and stores the value in *OUT; the per-call probability gate
 * lives inside this function so callers do not need to roll one
 * themselves.
 */
bool prop_ring_try_get(struct childdata *child,
		       const struct syscallrecord *rec,
		       unsigned long *out);
