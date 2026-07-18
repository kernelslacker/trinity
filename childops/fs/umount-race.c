/*
 * umount_race - race umount2(MNT_DETACH) against concurrent open/stat
 * readers on the shared scratch mounts the parent provisioned via
 * fds/scratch_block.c, all contained inside the inherited mount ns.
 *
 * Today's umount-vs-access teardown surface (detach_mounts vs
 * in-flight path lookups holding a struct path, MNT_DETACH lazy
 * unmount racing namespace_lock readers, the dput()/mntput()
 * interplay during umount_tree) is hard to reach in fuzz: a
 * per-child unshare(CLONE_NEWNS) yields a private mount-ns no
 * sibling can hold a path in, and a single-threaded child has no
 * concurrent accessor to race against.  Once the parent's startup
 * mount-ns provisioning latches the scratch mounts it set up are
 * visible to every child via fork() inheritance, and a brief fork()
 * inside this childop puts a real concurrent reader on the path
 * while we issue the umount.
 *
 * Per invocation: 1..MAX_CYCLES cycles.  Each cycle picks one
 * scratch_block pool entry whose mount_path is populated, snapshots
 * the path into a local buffer so a sibling-induced shm mutation
 * cannot redirect the target between fork() and umount2(), forks an
 * accessor helper that loops open/stat against the path, sleeps a
 * jittered microsecond budget, issues umount2(path, MNT_DETACH)
 * from the parent, then SIGTERM-reaps the helper.  No nested or
 * unbounded fan-out -- one helper per cycle, MAX_CYCLES cycles per
 * invocation, all bounded by the alarm(1) the parent arms before
 * dispatch.
 *
 * Gated identically to mount-churn.c.  When the parent's startup
 * mount-ns provisioning latched (shm->isolation.mnt_ready) AND the
 * scratch pool stood up (shm->isolation.scratch_block_ready), we
 * have a vetted target.  When either latch is false (non-root,
 * --no-startup-isolation, EPERM/ENOSYS in setup_startup_isolation,
 * pool init declined) the op returns byte-for-byte no-op -- zero
 * pool reads, zero syscalls -- so the pre-gate behaviour (this
 * childop was parked entirely) is preserved.  The unprivileged dev
 * workflow runs exactly as it did before the gate existed.
 *
 * Target source: shm->isolation.scratch_block[] ONLY.  The pool is
 * the box-safety chokepoint -- every mount visible there came out
 * of setup_startup_isolation() and lives inside the parent's private
 * mount-ns; no host mount can be named because the parent only
 * publishes entries it created and bound itself.
 *
 * Cap-block on the umount: the inherited mount-ns is owned by
 * init_user_ns and the child is nobody post-drop_privs, so umount2
 * almost always returns EPERM before deactivate_super runs --
 * exactly the same expected steady state mount-churn.c documents
 * for its per-cycle mount().  The EPERM is not the point: the
 * kernel-side path lookup (LOOKUP_DOWN walk + dentry references
 * the racing accessor may be holding), LSM security_sb_umount, and
 * the namespace_lock acquisition all run before may_umount()
 * rejects, and that is the coverage this op unlocks.  Successful
 * umount (root in the init_user_ns case) is a by-product, not the
 * gate -- if it does succeed the pool entry's mount goes away and
 * the next cycle's pick / next invocation cleanly sees ENOENT or
 * EINVAL and moves on.
 */

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "rnd.h"
#include "scratch_block.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/mount.h"
/*
 * Hard cap on race cycles per invocation.  Three is enough to sample
 * different temporal positions of the race window within one alarm(1),
 * and leaves headroom for the per-cycle fork/usleep/umount/reap chain
 * (~100 ms worst-case) under that ceiling.
 */
#define MAX_CYCLES		3U

/*
 * Accessor inner-loop wall-clock budget on CLOCK_MONOTONIC plus a
 * belt-and-braces iteration cap so a pathologically fast
 * open/close pair can't busy-loop forever even if clock_gettime
 * returned bad data.  The helper exits the moment either bound
 * trips, so an accessor that finished cleanly never costs the
 * reap_acceptor SIGTERM path.
 */
#define ACCESSOR_BUDGET_NS	(80LL * 1000LL * 1000LL)	/* 80 ms */
#define ACCESSOR_MAX_ITERS	512U

/*
 * Maximum parent-side usleep between fork() returning and the
 * umount2() syscall.  Sampled uniformly in [0, PARENT_USLEEP_MAX)
 * so successive invocations sample different temporal positions
 * relative to the accessor's inner loop ramp-up.
 */
#define PARENT_USLEEP_MAX	2000U

/*
 * Hot inner loop for the accessor helper.  Pull a struct path on
 * the mount via open(O_PATH | O_DIRECTORY) -- O_PATH so we don't
 * need read permission on the underlying inode and fast-paths
 * dentry walk, O_DIRECTORY so a non-directory inode short-circuits
 * to ENOTDIR rather than opening a regular file.  fstat() upgrades
 * the dentry walk into an inode reference the racing umount may
 * be tearing down.  A second bare stat() reissues the LOOKUP_DOWN
 * walk so each iteration starts fresh from /, which is the path
 * shape umount2(MNT_DETACH) itself walks in fs/namespace.c.
 *
 * Every errno is benign coverage: ENOENT/ESTALE mean the racing
 * umount won and the mount disappeared mid-iter (the success
 * signal for this op), EACCES means the dropped-privs child lost
 * a permission check post-walk (the walk still happened), EIO and
 * the rest keep pumping rather than exiting early so the budget
 * decides when to stop, not the first failure.
 */
static void accessor_loop(const char *path)
{
	struct timespec start;
	unsigned int i;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
		start.tv_sec = 0;
		start.tv_nsec = 0;
	}

	for (i = 0; i < ACCESSOR_MAX_ITERS; i++) {
		struct stat st;
		int fd;

		fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
		if (fd >= 0) {
			(void)fstat(fd, &st);
			close(fd);
		}

		(void)stat(path, &st);

		if (budget_elapsed_ns(&start, ACCESSOR_BUDGET_NS))
			break;
	}
}

/*
 * Random walk over the pool entries starting at a uniformly-picked
 * slot, returning the first index whose mount_path is populated.
 * Mirrors scratch_block_random_loop_num()'s "ignore tmpfs-only
 * slots" walk shape but filters on mount_path instead of loop_num
 * (tmpfs entries have mount_path set and are eligible targets;
 * loop-only entries with no mount published are not).  Returns
 * UINT_MAX when no entry qualifies.
 */
static unsigned int pick_mounted_index(unsigned int count)
{
	unsigned int start;
	unsigned int i;

	if (count == 0)
		return UINT_MAX;

	start = rnd_modulo_u32(count);
	for (i = 0; i < count; i++) {
		unsigned int idx = (start + i) % count;

		if (shm->isolation.scratch_block[idx].mount_path[0] != '\0')
			return idx;
	}
	return UINT_MAX;
}

/*
 * One umount-vs-access race cycle.  Snapshot the chosen mount_path
 * into a stack-local null-terminated buffer (defending against a
 * racing teardown that mutates shm mid-read) before fork() so the
 * helper and the umount target are derived from the same byte
 * sequence.  Caller bounds the cycle count; this routine bounds
 * the per-cycle wall-clock by the accessor budget plus the
 * parent's usleep and reap_acceptor cap.
 */
static void one_cycle(void)
{
	char path[sizeof(shm->isolation.scratch_block[0].mount_path)];
	unsigned int count;
	unsigned int idx;
	size_t n;
	pid_t pid;

	count = load_scratch_block_count();
	idx = pick_mounted_index(count);
	if (idx == UINT_MAX)
		return;

	/* strnlen + memcpy rather than snprintf("%s",...) so a torn
	 * read that lacks a trailing null inside the 96-byte field is
	 * clamped at the field boundary instead of running into the
	 * next struct member.  The provider always writes
	 * null-terminated content and never overwrites a published
	 * entry in place, so in steady state n is the original
	 * strlen; the strnlen bound is defence-in-depth. */
	n = strnlen(shm->isolation.scratch_block[idx].mount_path,
		    sizeof(path));
	if (n == 0 || n >= sizeof(path))
		return;
	memcpy(path, shm->isolation.scratch_block[idx].mount_path, n);
	path[n] = '\0';

	__atomic_add_fetch(&shm->stats.umount_race.picks, 1, __ATOMIC_RELAXED);

	pid = fork();
	if (pid < 0) {
		__atomic_add_fetch(&shm->stats.umount_race.setup_failed, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	if (pid == 0) {
		accessor_loop(path);
		_exit(0);
	}

	__atomic_add_fetch(&shm->stats.umount_race.forks, 1, __ATOMIC_RELAXED);

	(void)usleep(rnd_modulo_u32(PARENT_USLEEP_MAX));

	if (umount2(path, MNT_DETACH) == 0)
		__atomic_add_fetch(&shm->stats.umount_race.umounts, 1,
				   __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.umount_race.umount_failed, 1,
				   __ATOMIC_RELAXED);

	reap_acceptor(pid);
}

bool umount_race(struct childdata *child)
{
	unsigned int cycles;
	unsigned int i;

	__atomic_add_fetch(&shm->stats.umount_race.runs, 1, __ATOMIC_RELAXED);

	/* Box-safety + degrade gate, mirroring mount-churn.c's
	 * mnt_ready check (childops/fs/mount-churn.c:177).  When the
	 * parent's startup mount-ns provisioning didn't latch
	 * (non-root, --no-startup-isolation, EPERM/ENOSYS in
	 * setup_startup_isolation) the inherited "ns" is the host's,
	 * and the scratch pool is empty by construction
	 * (init_scratch_block bails on mnt_ready=0).  The pre-gate
	 * shape of this op was parked entirely; the byte-for-byte
	 * fallback below is a no-op (zero pool reads, zero syscalls)
	 * so the unprivileged dev workflow runs exactly as it did
	 * before this op existed. */
	if (!__atomic_load_n(&shm->isolation.mnt_ready, __ATOMIC_RELAXED))
		return true;
	if (!__atomic_load_n(&shm->isolation.scratch_block_ready,
			     __ATOMIC_RELAXED))
		return true;

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

	cycles = 1U + rnd_modulo_u32(MAX_CYCLES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < cycles; i++)
		one_cycle();

	return true;
}
