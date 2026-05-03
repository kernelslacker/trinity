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
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* Number of trinity-testfile? files we open private fds onto.  Matches
 * the MAX_TESTFILES bound in fds/testfiles.c so every testfile shows up
 * in our pool — keeps cross-process contention concentrated rather than
 * spread across files no one else is touching. */
#define NR_FLOCK_FDS	4

/* Hard cap on inner iterations.  Sized to leave the SIGALRM stall
 * detector ample headroom: at ~10us per blocked flock() round-trip the
 * worst-case loop completes well under the 1-second alarm. */
#define MAX_ITERATIONS	64

/* Per-fd lock state so we strictly alternate acquire/release.  Without
 * this we'd issue back-to-back LOCK_EX on the same fd, which the kernel
 * treats as a no-op upgrade and skips the contention path entirely. */
struct flock_slot {
	int fd;
	bool held;
};

static int open_one(unsigned int idx)
{
	char path[PATH_MAX + 32];

	snprintf(path, sizeof(path), "%s/trinity-testfile%u",
		 trinity_tmpdir_abs(), idx);
	return open(path, O_RDWR | O_CREAT, 0666);
}

bool flock_thrash(struct childdata *child)
{
	struct flock_slot slots[NR_FLOCK_FDS];
	unsigned int opened = 0;
	unsigned int iter;
	unsigned int i;

	(void)child;

	__atomic_add_fetch(&shm->stats.flock_thrash_runs, 1, __ATOMIC_RELAXED);

	for (i = 0; i < NR_FLOCK_FDS; i++) {
		int fd = open_one(1 + i);

		if (fd < 0)
			continue;
		slots[opened].fd = fd;
		slots[opened].held = false;
		opened++;
	}

	if (opened == 0)
		return true;

	for (iter = 0; iter < MAX_ITERATIONS; iter++) {
		struct flock_slot *s = &slots[(unsigned int)rand() % opened];
		int op;
		int rc;

		if (s->held) {
			op = LOCK_UN;
		} else {
			/* ~25% LOCK_SH, otherwise LOCK_EX.  Mixing in shared
			 * locks exercises the SH<->EX upgrade/downgrade
			 * waitqueue paths in addition to the EX-only fast
			 * path. */
			op = (rand() % 4 == 0) ? LOCK_SH : LOCK_EX;

			/* ~25% non-blocking.  Higher than the pure-variety
			 * mix because under cross-process contention the
			 * blocking acquire path can pin the child for the
			 * full alarm window if every other child is also
			 * holding LOCK_EX; the LOCK_NB sprinkle keeps the
			 * loop ticking and exercises the EWOULDBLOCK reject
			 * path the blocking variant skips. */
			if (rand() % 4 == 0)
				op |= LOCK_NB;
		}

		/* 1-in-RAND_NEGATIVE_RATIO sub the carefully-curated op for
		 * a garbage value — exercises sys_flock's argument validation
		 * (LOCK_MAND removal, unknown bit rejection) which the curated
		 * mix above never reaches. */
		rc = flock(s->fd, (int)RAND_NEGATIVE_OR(op));
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.flock_thrash_locks,
					   1, __ATOMIC_RELAXED);
			s->held = (op != LOCK_UN);
		} else {
			__atomic_add_fetch(&shm->stats.flock_thrash_failed,
					   1, __ATOMIC_RELAXED);
			/* EWOULDBLOCK on LOCK_NB is expected and benign;
			 * leave s->held alone so the next iteration retries.
			 * EINTR (alarm fired mid-syscall) is also normal —
			 * same handling.  Anything else (EBADF, ENOLCK)
			 * still drops through; the loop just keeps trying. */
		}
	}

	for (i = 0; i < opened; i++)
		close(slots[i].fd);

	return true;
}
