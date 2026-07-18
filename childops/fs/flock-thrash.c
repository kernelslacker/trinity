/*
 * flock_thrash - rapid flock(2) take/release churn on a small set of
 * shared files.
 *
 * Trinity's random_syscall path can issue flock() but only sporadically
 * and against arbitrary fds, so the kernel's file_lock allocator and the
 * per-inode flc_flock list rarely see sustained contention on the same
 * inodes.  flock_thrash closes that gap: it opens its own private fds
 * onto a small pool of shared files (the same trinity-testfile? files
 * the rest of the fuzzer uses) and in a tight bounded loop alternates
 * acquire/release on a randomly chosen fd, with a curated mix of
 * LOCK_EX, LOCK_SH, and LOCK_NB modes.
 *
 * Different children running flock_thrash concurrently each open
 * independent fds onto the same underlying inodes, so the kernel sees
 * cross-process contention on the per-inode lock list — exercising the
 * flock_lock_inode() acquire/release fast path, the file_lock cache
 * (kmem_cache_alloc/free of struct file_lock), the locks_wake_up_blocks
 * waiter chain, and the LOCK_NB -EWOULDBLOCK reject path.
 *
 * Self-bounding: the inner loop is capped at MAX_ITERATIONS, with
 * ~25% of acquire attempts using LOCK_NB so the child can't be pinned
 * indefinitely waiting for an exclusive lock another process holds.
 * The remaining blocking acquires are bounded by the SIGALRM the parent
 * arms before dispatching this op (alarm(1) in child.c) — a stuck
 * flock() returns EINTR and the loop moves on.  All locks acquired by
 * this op are released by close() before return; flock locks are tied
 * to the open file description and drop automatically when the last
 * reference closes.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

/* Number of trinity-testfile? files we open private fds onto.  Matches
 * the MAX_TESTFILES bound in fds/testfiles.c so every testfile shows up
 * in our pool — keeps cross-process contention concentrated rather than
 * spread across files no one else is touching. */
#define NR_FLOCK_FDS	4

/* Default cap on inner iterations.  Sized to leave the SIGALRM stall
 * detector ample headroom: at ~10us per blocked flock() round-trip the
 * worst-case loop completes well under the 1-second alarm.  This is
 * the BUDGETED() base — adapt_budget() can scale it from 0.25x to 4x
 * (16 to 256 iters) based on the recent kcov edge-rate signal. */
#define MAX_ITERATIONS	64

/* Per-fd lock state.  In ORDER_ALTERNATE we use s->held to strictly
 * alternate acquire/release; otherwise it's just bookkeeping the other
 * orderings consult to bias their choices.  Without alternation we'd
 * issue back-to-back LOCK_EX on the same fd, which the kernel treats as
 * a no-op upgrade and skips the contention path entirely — the LOOSE
 * order deliberately seeks that path out. */
struct flock_slot {
	int fd;
	bool held;
};

/* Per-invocation acquire/release ordering.  The default alternation
 * keeps every fd cycling through the same per-inode flc_flock list
 * states; varying the order surfaces races that only fire when the
 * list sees an unusual operation sequence. */
enum thrash_order {
	/* Baseline: strict acquire-then-release alternation. */
	ORDER_ALTERNATE,
	/* First half pure acquires, second half pure releases.  Pushes
	 * the per-inode list to its peak depth, then drains in random
	 * fd-pick order so locks_wake_up_blocks sees wakees that aren't
	 * the FIFO-oldest waiter. */
	ORDER_HOLD_BATCH,
	/* Ignore s->held: re-issue LOCK_EX on held slots (kernel hits the
	 * upgrade/conversion path the alternation avoids) and sometimes
	 * LOCK_UN on !held slots (no-op release fast path). */
	ORDER_LOOSE,
	NR_THRASH_ORDERS,
};

static void shuffle_slots(struct flock_slot *s, unsigned int n)
{
	unsigned int i;

	for (i = n; i > 1; i--) {
		unsigned int j = rnd_modulo_u32(i);
		struct flock_slot tmp = s[i - 1];

		s[i - 1] = s[j];
		s[j] = tmp;
	}
}

static int open_one(unsigned int idx)
{
	char path[PATH_MAX + 32];

	snprintf(path, sizeof(path), "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), idx);
	return open(path, O_RDWR | O_CREAT, 0666);
}

/*
 * Phase: open private fds onto the shared trinity-testfile? pool.
 * Returns the number of successfully populated slots (up to
 * NR_FLOCK_FDS; individual opens that fail are silently skipped).
 * Each populated entry starts with held=false; subsequent phases
 * drive acquire/release from there.
 */
static unsigned int flock_thrash_iter_open_slots(struct flock_slot *slots)
{
	unsigned int opened = 0;
	unsigned int i;

	for (i = 0; i < NR_FLOCK_FDS; i++) {
		int fd = open_one(1 + i);

		if (fd < 0)
			continue;
		slots[opened].fd = fd;
		slots[opened].held = false;
		opened++;
	}
	return opened;
}

/*
 * Phase: pick the flock op for this iteration based on the running
 * order and the slot's held state.  Sets *skip and returns 0 when
 * ORDER_HOLD_BATCH's phase gate wants this iter to no-op; otherwise
 * returns the op_used value with the RAND_NEGATIVE_OR edge-value
 * substitution already applied -- that substituted value is what the
 * kernel actually sees, so the caller must feed it to the apply phase
 * (not the pre-substitution op) for s->held bookkeeping to stay in
 * sync with kernel state.
 */
static int flock_thrash_iter_pick_op(enum thrash_order order,
				     const struct flock_slot *s,
				     unsigned int iter,
				     unsigned int phase_split,
				     bool *skip)
{
	int op;

	*skip = false;

	switch (order) {
	case ORDER_HOLD_BATCH:
		/* Phase 1: only acquire on !held slots; phase 2:
		 * only release on held slots.  Random fd picks make
		 * phase 2's release order a shuffle of acquire
		 * order, so wakeups don't follow the FIFO waiter
		 * sequence. */
		if (iter < phase_split) {
			if (s->held) {
				*skip = true;
				return 0;
			}
			op = (rnd_modulo_u32(4) == 0) ? LOCK_SH : LOCK_EX;
			if (rnd_modulo_u32(4) == 0)
				op |= LOCK_NB;
		} else {
			if (!s->held) {
				*skip = true;
				return 0;
			}
			op = LOCK_UN;
		}
		break;
	case ORDER_LOOSE:
		/* Don't gate on s->held.  1/8 LOCK_UN regardless of
		 * state hits the no-op release fast path when
		 * !held; LOCK_EX on a held slot exercises the
		 * conversion path (flock_lock_inode replacing the
		 * existing lock without going through the wait
		 * queue). */
		if (rnd_modulo_u32(8) == 0) {
			op = LOCK_UN;
		} else {
			op = (rnd_modulo_u32(4) == 0) ? LOCK_SH : LOCK_EX;
			if (rnd_modulo_u32(4) == 0)
				op |= LOCK_NB;
		}
		break;
	case ORDER_ALTERNATE:
	default:
		if (s->held) {
			op = LOCK_UN;
		} else {
			/* ~25% LOCK_SH, otherwise LOCK_EX.  Mixing
			 * in shared locks exercises the SH<->EX
			 * upgrade/downgrade waitqueue paths in
			 * addition to the EX-only fast path. */
			op = (rnd_modulo_u32(4) == 0) ? LOCK_SH : LOCK_EX;

			/* ~25% non-blocking.  Higher than the pure-
			 * variety mix because under cross-process
			 * contention the blocking acquire path can
			 * pin the child for the full alarm window
			 * if every other child is also holding
			 * LOCK_EX; the LOCK_NB sprinkle keeps the
			 * loop ticking and exercises the
			 * EWOULDBLOCK reject path the blocking
			 * variant skips. */
			if (rnd_modulo_u32(4) == 0)
				op |= LOCK_NB;
		}
		break;
	}

	/* 1-in-RAND_NEGATIVE_RATIO sub the carefully-curated op for
	 * a garbage value — exercises sys_flock's argument validation
	 * (LOCK_MAND removal, unknown bit rejection) which the curated
	 * mix above never reaches.  Returning the substituted value
	 * lets the apply phase reconcile s->held against what the
	 * kernel actually applied rather than the original
	 * (pre-substitution) op — otherwise an accepted garbage value
	 * drifts the lock-state model and the loop may e.g. issue
	 * LOCK_EX believing the lock is already held. */
	return (int)RAND_NEGATIVE_OR(op);
}

/*
 * Phase: issue the flock() and reconcile s->held against what the
 * kernel actually applied.  On success, s->held is updated only when
 * op_used (post RAND_NEGATIVE_OR substitution) matches a recognised
 * LOCK_SH/EX/UN constant -- an accepted edge-value garbage op would
 * otherwise poison the lock-state model.  Failures (EWOULDBLOCK from
 * LOCK_NB, EINTR from a fired alarm, or anything else like EBADF /
 * ENOLCK) leave s->held untouched so the next iter just retries.
 */
static void flock_thrash_iter_apply(struct flock_slot *s, int op_used)
{
	int rc = flock(s->fd, op_used);

	if (rc == 0) {
		int op_base = op_used & ~LOCK_NB;

		__atomic_add_fetch(&shm->stats.flock_thrash.locks,
				   1, __ATOMIC_RELAXED);
		if (op_base == LOCK_SH || op_base == LOCK_EX ||
		    op_base == LOCK_UN)
			s->held = (op_base != LOCK_UN);
	} else {
		__atomic_add_fetch(&shm->stats.flock_thrash.failed,
				   1, __ATOMIC_RELAXED);
	}
}

/*
 * Phase: release the slot pool.  Half the time close in open order
 * (FIFO), the other half shuffled -- close-driven release walks the
 * per-inode flc_flock list in a different order than the explicit
 * LOCK_UN path, and varying it keeps any latent assumption about
 * close sequence honest.  flock locks tied to the open file
 * description drop automatically on the last close(), so we don't
 * need to issue LOCK_UN for slots that are still held.
 */
static void flock_thrash_iter_teardown(struct flock_slot *slots,
				       unsigned int opened)
{
	unsigned int i;

	if (rnd_modulo_u32(2) == 0)
		shuffle_slots(slots, opened);
	for (i = 0; i < opened; i++)
		close(slots[i].fd);
}

bool flock_thrash(struct childdata *child)
{
	struct flock_slot slots[NR_FLOCK_FDS];
	unsigned int opened;
	unsigned int iter, iter_cap, phase_split;
	enum thrash_order order;

	__atomic_add_fetch(&shm->stats.flock_thrash.runs, 1, __ATOMIC_RELAXED);

	opened = flock_thrash_iter_open_slots(slots);
	if (opened == 0)
		return true;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	iter_cap = BUDGETED(CHILD_OP_FLOCK_THRASH, JITTER_RANGE(MAX_ITERATIONS));
	order = (enum thrash_order)rnd_modulo_u32(NR_THRASH_ORDERS);
	phase_split = iter_cap / 2;
	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (iter = 0; iter < iter_cap; iter++) {
		struct flock_slot *s = &slots[rnd_modulo_u32(opened)];
		bool skip;
		int op_used;

		op_used = flock_thrash_iter_pick_op(order, s, iter,
						    phase_split, &skip);
		if (skip)
			continue;
		flock_thrash_iter_apply(s, op_used);
	}

	flock_thrash_iter_teardown(slots, opened);
	return true;
}
