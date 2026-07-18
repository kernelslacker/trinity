/*
 * pipe_thrash - rapid pipe()/pipe2()/socketpair()/close() churn.
 *
 * Trinity's random_syscall path eventually issues pipe/pipe2/socketpair,
 * but interleaved with thousands of other syscalls.  The kernel's fd
 * allocator (alloc_fd / __fd_install / __close), the pipe-inode and
 * unix-socket allocation slabs, and the per-task files_struct->fdtable
 * resize logic only get bursty pressure when many of these fire back-
 * to-back from the same task.
 *
 * pipe_thrash closes that gap.  In a tight bounded loop it issues a
 * curated mix of:
 *   - pipe(2)
 *   - pipe2(2) with random combinations of O_CLOEXEC|O_NONBLOCK|O_DIRECT
 *     (the only flags pipe2 accepts; O_DIRECT switches the pipe into
 *     packet mode and exercises a separate read/write code path)
 *   - socketpair(AF_UNIX, SOCK_STREAM|SOCK_DGRAM|SOCK_SEQPACKET, 0)
 * and immediately closes the returned fds in a randomised order.  The
 * randomised close order keeps the fdtable's "next available slot"
 * cursor jumping around so every iteration replays alloc_fd's
 * find-first-zero-bit scan instead of trivially reusing the last freed
 * slot.
 *
 * Self-bounding: the op exits at the first of (a) PIPE_THRASH_BUDGET_NS
 * wall-clock elapsed, or (b) MAX_ITERATIONS create-syscalls issued.
 * Both bounds are small enough that the SIGALRM stall detector in
 * child.c can still fire if an alloc path wedges.  Any leftover open
 * fds from the final partially-filled batch are closed before return so
 * the op leaves no fd debt for the rest of the child.
 */

#include <stdbool.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "jitter.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
/* Wall-clock ceiling per invocation.  Sits in the 150-250ms band the
 * other recent storm childops use so dump_stats still ticks regularly
 * and SIGALRM-based stall detection still has headroom to fire. */
#define PIPE_THRASH_BUDGET_NS	200000000L	/* 200 ms */

/* Hard upper bound on create-syscalls per invocation.  Each syscall
 * yields 2 fds, so at the cap we can hold 512 fds open transiently if
 * we never closed in between — instead we drain the batch buffer
 * whenever it fills, keeping peak fd usage at FD_BATCH.  This is the
 * BUDGETED() base — adapt_budget() can scale it from 0.25x to 4x
 * (64 to 1024 iters) based on the recent kcov edge-rate signal. */
#define MAX_ITERATIONS		256

/* Number of fds buffered before we shuffle-and-close.  Sized so that
 * each batch corresponds to ~8 create-syscalls (2 fds each), keeping
 * peak fd consumption modest while still giving alloc_fd a non-trivial
 * window to scan over when the next batch starts. */
#define FD_BATCH		16

/*
 * Accepted pipe2 flag combinations.  pipe2 rejects anything outside
 * (O_CLOEXEC|O_NONBLOCK|O_DIRECT); we enumerate the legal subset so
 * every call lands in the kernel and exercises the requested code path
 * instead of bouncing on -EINVAL.  0 (plain pipe2 with no flags) is
 * included so we cover the "pipe2 == pipe" fast path too.
 */
static const unsigned long pipe2_flags[] = {
	0,
	O_CLOEXEC,
	O_NONBLOCK,
	O_DIRECT,
	O_CLOEXEC | O_NONBLOCK,
	O_CLOEXEC | O_DIRECT,
	O_NONBLOCK | O_DIRECT,
	O_CLOEXEC | O_NONBLOCK | O_DIRECT,
};

static const unsigned long socketpair_types[] = {
	SOCK_STREAM,
	SOCK_DGRAM,
	SOCK_SEQPACKET,
};

/*
 * Drain the fd batch in randomised order.  Fisher-Yates shuffle so
 * close() sees the fds out of allocation order, defeating the
 * fdtable's natural LIFO reuse pattern and keeping alloc_fd's
 * find-first-zero-bit scan honest on the next batch.
 */
static void shuffle_close(int *fds, unsigned int n)
{
	unsigned int i;

	for (i = n; i > 1; i--) {
		unsigned int j = rnd_modulo_u32(i);
		int tmp = fds[i - 1];

		fds[i - 1] = fds[j];
		fds[j] = tmp;
	}

	for (i = 0; i < n; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
}

bool pipe_thrash(struct childdata *child)
{
	struct timespec start;
	int batch[FD_BATCH];
	unsigned int filled = 0;
	unsigned int iter;
	unsigned int iters = BUDGETED(CHILD_OP_PIPE_THRASH, JITTER_RANGE(MAX_ITERATIONS));

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.pipe_thrash.runs, 1, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}
	for (iter = 0; iter < iters; iter++) {
		int pair[2] = { -1, -1 };
		int rc;
		unsigned int which = rnd_modulo_u32(3);

		switch (which) {
		case 0:
			rc = pipe(pair);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.pipe_thrash.pipes,
						   1, __ATOMIC_RELAXED);
			break;
		case 1:
			rc = pipe2(pair,
				   (int)RAND_NEGATIVE_OR(pipe2_flags[rnd_modulo_u32(ARRAY_SIZE(pipe2_flags))]));
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.pipe_thrash.pipes,
						   1, __ATOMIC_RELAXED);
			break;
		default:
			rc = socketpair(AF_UNIX,
					(int)socketpair_types[rnd_modulo_u32(ARRAY_SIZE(socketpair_types))],
					0, pair);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.pipe_thrash.socketpairs,
						   1, __ATOMIC_RELAXED);
			break;
		}

		if (rc != 0) {
			__atomic_add_fetch(&shm->stats.pipe_thrash.alloc_failed,
					   1, __ATOMIC_RELAXED);
			/* Don't busy-loop on a saturated alloc path: an
			 * EMFILE/ENFILE storm here would just spin until the
			 * iteration cap with no useful work.  Drain whatever
			 * is buffered and exit early. */
			break;
		}

		batch[filled++] = pair[0];
		batch[filled++] = pair[1];

		if (filled + 2 > FD_BATCH) {
			shuffle_close(batch, filled);
			filled = 0;
		}

		if (budget_elapsed_ns(&start, PIPE_THRASH_BUDGET_NS))
			break;
	}

	if (filled > 0)
		shuffle_close(batch, filled);

	return true;
}
