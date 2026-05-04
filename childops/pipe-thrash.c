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

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Wall-clock ceiling per invocation.  Sits in the 150-250ms band the
 * other recent storm childops use so dump_stats still ticks regularly
 * and SIGALRM-based stall detection still has headroom to fire. */
#define PIPE_THRASH_BUDGET_NS	200000000L	/* 200 ms */

/* Hard upper bound on create-syscalls per invocation.  Each syscall
 * yields 2 fds, so at the cap we can hold 512 fds open transiently if
 * we never closed in between — instead we drain the batch buffer
 * whenever it fills, keeping peak fd usage at FD_BATCH. */
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
static const int pipe2_flags[] = {
	0,
	O_CLOEXEC,
	O_NONBLOCK,
	O_DIRECT,
	O_CLOEXEC | O_NONBLOCK,
	O_CLOEXEC | O_DIRECT,
	O_NONBLOCK | O_DIRECT,
	O_CLOEXEC | O_NONBLOCK | O_DIRECT,
};

static const int socketpair_types[] = {
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
		unsigned int j = (unsigned int)(rand() % (int)i);
		int tmp = fds[i - 1];

		fds[i - 1] = fds[j];
		fds[j] = tmp;
	}

	for (i = 0; i < n; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
}

static bool budget_elapsed(const struct timespec *start)
{
	struct timespec now;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (now.tv_sec  - start->tv_sec)  * 1000000000L
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= PIPE_THRASH_BUDGET_NS;
}

bool pipe_thrash(struct childdata *child)
{
	struct timespec start;
	int batch[FD_BATCH];
	unsigned int filled = 0;
	unsigned int iter;
	unsigned int iters = JITTER_RANGE(MAX_ITERATIONS);

	(void)child;

	__atomic_add_fetch(&shm->stats.pipe_thrash_runs, 1, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (iter = 0; iter < iters; iter++) {
		int pair[2] = { -1, -1 };
		int rc;
		unsigned int op = (unsigned int)rand() % 3;

		switch (op) {
		case 0:
			rc = pipe(pair);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.pipe_thrash_pipes,
						   1, __ATOMIC_RELAXED);
			break;
		case 1:
			rc = pipe2(pair,
				   (int)RAND_NEGATIVE_OR(pipe2_flags[rand() % (int)ARRAY_SIZE(pipe2_flags)]));
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.pipe_thrash_pipes,
						   1, __ATOMIC_RELAXED);
			break;
		default:
			rc = socketpair(AF_UNIX,
					socketpair_types[rand() % (int)ARRAY_SIZE(socketpair_types)],
					0, pair);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.pipe_thrash_socketpairs,
						   1, __ATOMIC_RELAXED);
			break;
		}

		if (rc != 0) {
			__atomic_add_fetch(&shm->stats.pipe_thrash_alloc_failed,
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

		if (budget_elapsed(&start))
			break;
	}

	if (filled > 0)
		shuffle_close(batch, filled);

	return true;
}
