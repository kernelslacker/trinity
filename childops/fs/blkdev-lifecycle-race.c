/*
 * blkdev_lifecycle_race - concurrent /dev/loop$N open/LOOP_SET_FD/CLR_FD
 * vs BLKRRPART/BLKFLSBUF on the same node from a sibling thread.
 *
 * Targets a recurring cluster on the loop driver lifecycle path:
 * bdev_open / sync_bdevs / bdev_release / blkdev_fallocate /
 * queue_limits_commit_update_frozen hangs and softlockups, and the
 * lo_rw_aio GPF / bioset_exit deadlock / blk_mq_free_rqs slab-OOB
 * shapes that surface when partition-rescan (BLKRRPART, which freezes
 * the request queue) overlaps loop_attr_*_show, lo_open, lo_release,
 * or LOOP_CLR_FD on the same backing device.  The race window is
 * inside the kernel's blk_mq_freeze_queue / __loop_clr_fd transition;
 * a single-threaded fuzzer never lands it because BLKRRPART blocks on
 * the same mutex LOOP_CLR_FD takes, and the racing thread has to be
 * already mid-syscall when the lifecycle thread enters teardown.
 *
 * Two-pthread design (matches the canonical pthread_create shape used
 * by close_racer / bridge_conntrack_churn):
 *   Thread A (lifecycle) rotates: open /dev/loop$N, LOOP_SET_FD against
 *     a memfd-backed file truncated to a randomised power-of-two size,
 *     mix of BLKFLSBUF / fsync / fallocate(PUNCH_HOLE|KEEP_SIZE) on the
 *     loop fd, LOOP_CLR_FD, close.  N is drawn from the scratch_block
 *     pool (fds/scratch_block.c) so the device exercised here is always
 *     a parent-vetted loop allocated via LOOP_CTL_GET_FREE -- a host
 *     loop number cannot leak in.
 *   Thread B (rescan thrash) tightly opens the same /dev/loop$N and
 *     fires BLKRRPART + BLKFLSBUF + close in a loop.  Stops when thread
 *     A signals via a g_thread_b_stop atomic; thread A always waits a
 *     bounded interval before flipping the stop flag, then pthread_joins.
 *
 * Box-safety gate: the entry point bails when the scratch_block pool
 * has no loop entry (scratch_block_random_loop_num() returns -1).
 * That covers the non-root degrade path (no parent mount-ns -> no
 * pool), absent /dev/loop-control, exhausted loop pool, and
 * --no-startup-isolation.  Latches ns_unsupported once observed so
 * subsequent invocations short-circuit without a fresh pool query.
 *
 * Self-bounding: per-iter wall-clock cap (~150ms band) inside thread B
 * and a hard BUDGETED iteration cap on thread A.  child.c's SIGALRM(1s)
 * is the outer backstop.  EBUSY / ENXIO / EPERM on LOOP_SET_FD are
 * expected (the pool's parent-held loop_fd keeps the backing
 * configured for the run; a sibling lifecycle worker also holds the
 * dev) -- counted, not failure.
 *
 * DORMANT in dormant_op_disabled[].  Dave smoke-tests before fleet
 * enable.  No module load, no persistent state outside the per-cycle
 * /dev/loop$N association which LOOP_CLR_FD always tears down.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "syscall-gate.h"
#include "scratch_block.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/loop.h>) && __has_include(<linux/fs.h>) && \
    __has_include(<linux/falloc.h>)

#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/loop.h>

#include "random.h"

#include "kernel/fcntl.h"
#include "kernel/falloc.h"
#include "kernel/memfd.h"
#define BLKDEV_BACKING_MIN	4096U	/* 4 KiB */
#define BLKDEV_BACKING_MAX	(16U << 20)	/* 16 MiB */
#define BLKDEV_RESCAN_BURST	8U	/* thread B inner cycles per spawn */
#define BLKDEV_ITERS_BASE	64U	/* BUDGETED scale base */
#define BLKDEV_ITERS_CAP	256U
#define BLKDEV_RESCAN_NS	(150L * 1000L * 1000L)	/* 150ms cap */

static bool ns_unsupported_blkdev_lifecycle;
static atomic_int g_thread_b_stop;

struct blkdev_rescan_arg {
	int loop_n;
};

static int blkdev_loop_open(int n, int flags)
{
	char path[32];

	(void)snprintf(path, sizeof(path), "/dev/loop%d", n);
	return open(path, flags);
}

/*
 * Pull a vetted loop number from the scratch_block pool.  Returns
 * -1 when no loop entry is available (non-root, mnt_ready degraded,
 * /dev/loop-control absent, pool fully tmpfs-only), and latches
 * ns_unsupported on first absence so subsequent invocations
 * short-circuit at the top of the entry point without re-querying.
 * @child is the caller's struct childdata so the same NS_UNSUPPORTED
 * verdict can be recorded in childop_latch_reason[op_type] alongside
 * the static-bool latch.
 *
 * The pool is a process-wide singleton populated once in the parent
 * before fork(); a sentinel today is permanent for this process's
 * lifetime, so the latch is correct.
 */
static int blkdev_pick_loop_num(struct childdata *child)
{
	int n;

	n = scratch_block_random_loop_num();
	if (n < 0) {
		ns_unsupported_blkdev_lifecycle = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern the child.c dispatch loop uses for the
		 * unguarded write that motivated this guard. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
	}
	return n;
}

/*
 * Round @x up to the next power of two within [BLKDEV_BACKING_MIN,
 * BLKDEV_BACKING_MAX].  Loop devices are happiest with power-of-two
 * backing-file sizes — odd sizes get rounded up internally and we want
 * the rounding to be a no-op so the per-iter window stays predictable.
 */
static off_t blkdev_pick_size(void)
{
	unsigned int span = BLKDEV_BACKING_MAX - BLKDEV_BACKING_MIN + 1U;
	unsigned int raw = BLKDEV_BACKING_MIN + rnd_modulo_u32(span);
	off_t v = 1;

	while ((unsigned int)v < raw && v < (off_t)BLKDEV_BACKING_MAX)
		v <<= 1;
	return v;
}

static void *blkdev_rescan_thread(void *arg)
{
	struct blkdev_rescan_arg *ra = arg;
	unsigned int i;

	for (i = 0; i < BLKDEV_RESCAN_BURST; i++) {
		int fd;

		if (atomic_load_explicit(&g_thread_b_stop, memory_order_acquire))
			break;

		fd = blkdev_loop_open(ra->loop_n,
				      O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;

		/* BLKRRPART takes the queue freeze; BLKFLSBUF rides the same
		 * lock the close path needs.  Either ordering exercises the
		 * race window. */
		(void)ioctl(fd, BLKRRPART);
		__atomic_add_fetch(&shm->stats.blkdev_lifecycle.rescans,
				   1, __ATOMIC_RELAXED);
		(void)ioctl(fd, BLKFLSBUF);
		close(fd);
	}
	return NULL;
}

/*
 * One full lifecycle cycle on /dev/loop$N: open, attach a fresh
 * memfd-backed file via LOOP_SET_FD, mix of flush/fsync/fallocate to
 * drive blkdev_fallocate + sync_bdevs paths, LOOP_CLR_FD, close.
 * EBUSY / ENXIO / EPERM on LOOP_SET_FD are the ordinary outcomes when
 * a sibling is mid-cycle on the same node — count and continue.
 */
static void blkdev_lifecycle_cycle(int loop_n)
{
	off_t backing_size = blkdev_pick_size();
	int loop_fd, backing_fd, rc;

	backing_fd = (int)trinity_raw_syscall(__NR_memfd_create, "trinity-blkdev",
				  MFD_CLOEXEC);
	if (backing_fd < 0)
		return;
	if (ftruncate(backing_fd, backing_size) < 0) {
		close(backing_fd);
		return;
	}

	loop_fd = blkdev_loop_open(loop_n, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (loop_fd < 0) {
		close(backing_fd);
		return;
	}

	rc = ioctl(loop_fd, LOOP_SET_FD, (unsigned long)backing_fd);
	if (rc < 0) {
		if (errno == EBUSY || errno == ENXIO || errno == EPERM)
			__atomic_add_fetch(&shm->stats.blkdev_lifecycle.ebusy,
					   1, __ATOMIC_RELAXED);
		close(loop_fd);
		close(backing_fd);
		return;
	}
	__atomic_add_fetch(&shm->stats.blkdev_lifecycle.set_fd_ok,
			   1, __ATOMIC_RELAXED);

	/* Mix of teardown-adjacent IO ops.  Order is randomised per cycle
	 * so the race window against thread B's BLKRRPART lands in
	 * different sub-paths (sync_bdevs vs blkdev_fallocate vs the
	 * queue-freeze edge of BLKFLSBUF). */
	switch (rand32() & 0x3U) {
	case 0:
		(void)ioctl(loop_fd, BLKFLSBUF);
		break;
	case 1:
		(void)fsync(loop_fd);
		break;
	case 2:
		(void)fallocate(loop_fd,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				0, backing_size);
		break;
	default:
		(void)ioctl(loop_fd, BLKFLSBUF);
		(void)fsync(loop_fd);
		break;
	}

	(void)ioctl(loop_fd, LOOP_CLR_FD);
	__atomic_add_fetch(&shm->stats.blkdev_lifecycle.clr_fd, 1,
			   __ATOMIC_RELAXED);
	close(loop_fd);
	close(backing_fd);
}

bool blkdev_lifecycle_race(struct childdata *child)
{
	struct blkdev_rescan_arg ra;
	pthread_t tid;
	bool spawned = false;
	unsigned int iters, i;
	struct timespec gap = { .tv_sec = 0, .tv_nsec = BLKDEV_RESCAN_NS };

	__atomic_add_fetch(&shm->stats.blkdev_lifecycle.runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_unsupported_blkdev_lifecycle)
		return true;

	ra.loop_n = blkdev_pick_loop_num(child);
	if (ra.loop_n < 0) {
		__atomic_add_fetch(&shm->stats.blkdev_lifecycle.setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}
	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	atomic_store_explicit(&g_thread_b_stop, 0, memory_order_release);
	if (pthread_create(&tid, NULL, blkdev_rescan_thread, &ra) == 0)
		spawned = true;

	iters = BUDGETED(CHILD_OP_BLKDEV_LIFECYCLE_RACE, BLKDEV_ITERS_BASE);
	if (iters > BLKDEV_ITERS_CAP)
		iters = BLKDEV_ITERS_CAP;
	if (iters == 0U)
		iters = 1U;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < iters; i++)
		blkdev_lifecycle_cycle(ra.loop_n);

	if (spawned) {
		(void)nanosleep(&gap, NULL);
		atomic_store_explicit(&g_thread_b_stop, 1,
				      memory_order_release);
		(void)pthread_join(tid, NULL);
	}
	return true;
}

#else  /* !__has_include(<linux/loop.h>) */

bool blkdev_lifecycle_race(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.blkdev_lifecycle.runs, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.blkdev_lifecycle.setup_failed, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/loop.h>) */
