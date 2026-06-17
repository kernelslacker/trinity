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

/*
 * Object-kind tag for a captured scalar.  SCALAR_UNTYPED is the slot-0
 * sentinel and covers the OBJ_NONE generic-return case (anything pushed
 * by prop_ring_push() with no typed registrar attached -- the bulk of
 * the ring's traffic).  The typed kinds are populated by
 * prop_ring_push_scalar() callers whose own registrar already accepted
 * the value as a specific cookie / id; they let typed consumers (the
 * gen_arg_* handlers for ARG_KEY_SERIAL / ARG_TIMERID / ARG_SEM_ID /
 * ARG_MSG_ID / ARG_SYSV_SHM / ARG_PID) prefer same-kind history over
 * raw randoms while keeping the untyped consumer path's draws away
 * from typed values it has no business replaying as flags / lengths /
 * opaque ints.
 *
 * Kept distinct from enum objecttype because the consumer-relevant
 * partition is narrower than the full object-pool taxonomy: every
 * OBJ_FD_* maps to "fd, owned by the fd pool, not us"; many typed
 * scalars (watch descriptors, mountfd source ids, BPF object ids,
 * mqueue ids) collapse to the same SCALAR_* bucket regardless of which
 * specific kernel API minted them.  Stretch slots are reserved up front
 * so future capture sites can land their tags without an enum churn.
 */
enum scalar_kind {
	SCALAR_UNTYPED = 0,	/* generic scalar from prop_ring_push() */
	SCALAR_KEY_SERIAL,	/* kernel keyring key_serial_t */
	SCALAR_TIMER_ID,	/* POSIX timer_t from timer_create */
	SCALAR_SYSV_SEM,	/* SysV semaphore set id (semget) */
	SCALAR_SYSV_MSG,	/* SysV message queue id (msgget) */
	SCALAR_SYSV_SHM,	/* SysV shared memory id (shmget) */
	SCALAR_PID,		/* pid handed back by fork/clone/waitpid */
	SCALAR_WATCH_DESC,	/* inotify/fanotify/watch_queue descriptor */
	SCALAR_MOUNT_ID,	/* new mount API mount-id */
	SCALAR_BPF_ID,		/* BPF object id (prog/map/link/btf) */
	SCALAR_NR_KINDS,
};

struct prop_slot {
	unsigned long	value;		/* returned scalar */
	unsigned long	captured_at;	/* child->op_nr snapshot at capture */
	unsigned int	src_nr;		/* syscall index that produced value */
	enum scalar_kind kind;		/* what the value represents */
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
 * Mirror a typed scalar return into the owning child's propagation
 * ring, tagged with KIND so a same-kind consumer can prefer it later.
 * Bypasses prop_ring_push()'s OBJ_NONE gate -- the gate exists to
 * keep fd/pid-typed objects from leaking into the SCALAR_UNTYPED slot
 * pool, and is preserved on that path; this variant is for typed
 * integer cookies whose own registrar has already accepted the value
 * and which can safely be replayed.  Looks up the owning child via
 * this_child(); no-op if called outside a child context.  KIND must
 * be a typed bucket (not SCALAR_UNTYPED, not SCALAR_NR_KINDS).
 */
void prop_ring_push_scalar(unsigned int nr, long scalar_val,
			   enum scalar_kind kind);

/*
 * Try to pull a recent return value out of CHILD's ring for injection
 * as an input arg to the syscall described by REC.  On success returns
 * true and stores the value in *OUT; the per-call probability gate
 * lives inside this function so callers do not need to roll one
 * themselves.  Kind-agnostic -- accepts a slot of any tag (the
 * original behaviour pre-typing).  Used by the untyped consumer sites
 * (gen_undefined_arg / handle_arg_op).
 */
bool prop_ring_try_get(struct childdata *child,
		       const struct syscallrecord *rec,
		       unsigned long *out);

/*
 * Typed variant of prop_ring_try_get().  KIND must be a typed bucket;
 * normally matches only slots tagged with the same kind, with a low-
 * rate UNTYPED-grade escape hatch (~1-in-N) accepting any slot so the
 * ring keeps a chaos contribution even when the same-kind population
 * is empty or stale.  Same per-call probability gate as
 * prop_ring_try_get().  On a same-kind fire, bumps the per-kind
 * consume counter in kcov_shm; on an escape-hatch fire, bumps the
 * escape-hatch counter.  Currently consumed by typed callsites in
 * generate-args.c gated on child->prop_ring_typed_arm_b so the
 * shadow telemetry never perturbs the Arm A control's RNG.
 */
bool prop_ring_try_get_kind(struct childdata *child,
			    const struct syscallrecord *rec,
			    enum scalar_kind kind,
			    unsigned long *out);
