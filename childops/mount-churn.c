/*
 * mount_churn - rapid mount/umount cycles in a private mount namespace
 * to exercise superblock alloc/free, mount tree linkage, and the
 * deactivate_super RCU/refcount machinery.
 *
 * fs_lifecycle (childops/fs-lifecycle.c) drives a full mount→use→umount
 * sequence per invocation, with significant time spent on per-fs file
 * operations (fallocate, xattr, copy_file_range, ...).  mount_churn
 * cuts the use phase entirely: each cycle is mount→umount with no IO
 * in between, so per-invocation throughput is dominated by the mount
 * syscall itself.  That keeps sustained pressure on the paths
 * fs_lifecycle visits only sporadically:
 *   - alloc_super / deactivate_super
 *   - sget_fc / get_tree_nodev superblock cache lookups
 *   - mnt_alloc / mnt_release and the mount-list locking under
 *     namespace_sem
 *   - tmpfs/proc/sysfs ->kill_sb teardown back-to-back
 *
 * Per invocation: 1..MAX_CYCLES cycles.  Each cycle picks one of
 * tmpfs/proc/sysfs and a random subset of the safe MS_* flag set.
 *
 * Bounded to a child mount namespace via unshare(CLONE_NEWNS) on first
 * entry, with the root remarked MS_REC|MS_PRIVATE so nothing
 * propagates back to the host mount table.  If unshare or the first
 * mount fails (unprivileged, no CONFIG_NAMESPACES, etc.) a per-process
 * latch turns subsequent invocations into no-ops — there's no point
 * spinning on EPERM.
 *
 * Flag set is curated to the subset that's safe to combine freely with
 * the chosen fstype: MS_NOEXEC, MS_NOSUID, MS_NODEV, MS_RDONLY,
 * MS_NOATIME, MS_NODIRATIME, MS_RELATIME, MS_SYNCHRONOUS.  Deliberately
 * excluded: MS_BIND (needs a source), MS_MOVE (rearranges live tree),
 * MS_REMOUNT (changes options on existing mount; not what this op is
 * about), MS_SHARED/PRIVATE/SLAVE/UNBINDABLE (propagation control,
 * already handled by the namespace setup), MS_REC (nothing to recurse
 * into on a fresh mount).
 *
 * Self-bounding: the inner loop is hard-capped at MAX_CYCLES, every
 * mount is matched by an immediate umount2(MNT_DETACH) attempt (or a
 * graceful skip if mount failed), and the alarm(1) the parent arms
 * before dispatch bounds wall-clock time.  Per-(pid, counter) base
 * paths so concurrent children don't collide.
 */

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"	/* ARRAY_SIZE */

/* Hard cap on mount/umount cycles per invocation.  Kept modest so a
 * single op completes well inside the alarm(1) window even when the
 * VFS is under contention from sibling churners. */
#define MAX_CYCLES	16

/* Latched per-child: private mount namespace is in place. */
static bool ns_unshared;
/* Latched per-child: namespace or first mount denied. */
static bool ns_unsupported;

/* Per-process monotonic counter so each mountpoint name within a
 * child is distinct.  Doesn't need to be atomic — only this child
 * uses it. */
static unsigned long mount_churn_seq;

static const char * const fstypes[] = {
	"tmpfs",
	"proc",
	"sysfs",
};

/* Safe flag set: each is a per-mount option that does not change the
 * shape of the mount tree and combines freely with fresh tmpfs/proc/
 * sysfs mounts. */
static const unsigned long safe_flags[] = {
	MS_NOEXEC,
	MS_NOSUID,
	MS_NODEV,
	MS_RDONLY,
	MS_NOATIME,
	MS_NODIRATIME,
	MS_RELATIME,
	MS_SYNCHRONOUS,
};

static unsigned long pick_flags(void)
{
	unsigned long flags = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(safe_flags); i++) {
		if (RAND_BOOL())
			flags |= safe_flags[i];
	}
	/* MS_NOATIME and MS_RELATIME are mutually exclusive; if both got
	 * picked, drop MS_RELATIME so the kernel doesn't reject the
	 * mount with EINVAL on every other invocation. */
	if ((flags & MS_NOATIME) && (flags & MS_RELATIME))
		flags &= ~MS_RELATIME;
	return flags;
}

static bool ensure_private_ns(void)
{
	if (ns_unshared)
		return true;
	if (ns_unsupported)
		return false;

	if (unshare(CLONE_NEWNS) != 0) {
		ns_unsupported = true;
		return false;
	}

	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		ns_unsupported = true;
		output(0, "mount_churn: MS_PRIVATE remount failed (errno=%d), disabling\n",
		       errno);
		return false;
	}

	ns_unshared = true;
	return true;
}

bool mount_churn(struct childdata *child)
{
	unsigned int cycles;
	unsigned int i;
	pid_t pid = getpid();

	(void)child;

	__atomic_add_fetch(&shm->stats.mount_churn_runs, 1, __ATOMIC_RELAXED);

	if (!ensure_private_ns())
		return true;

	cycles = 1 + ((unsigned int)rand() % MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		const char *fstype = fstypes[(unsigned int)rand() % ARRAY_SIZE(fstypes)];
		unsigned long flags = pick_flags();
		unsigned long seq = ++mount_churn_seq;
		char path[PATH_MAX + 64];

		snprintf(path, sizeof(path),
			 "%s/trinity-mountchurn-%d-%lu",
			 trinity_tmpdir_abs(), (int)pid, seq);

		if (mkdir(path, 0755) != 0) {
			__atomic_add_fetch(&shm->stats.mount_churn_failed,
					   1, __ATOMIC_RELAXED);
			/* EEXIST is extremely unlikely with pid+seq
			 * names; ENOSPC/EROFS/EACCES on the cwd mean
			 * we can't even create mountpoints — bail. */
			if (errno == EROFS || errno == EACCES ||
			    errno == ENOSPC || errno == EPERM)
				return true;
			continue;
		}

		if (mount(fstype, path, fstype, flags, NULL) != 0) {
			__atomic_add_fetch(&shm->stats.mount_churn_failed,
					   1, __ATOMIC_RELAXED);
			/* EPERM here means the namespace setup didn't
			 * give us mount caps after all (e.g. unprivileged
			 * userns without the right bits) — latch and
			 * bail.  ENODEV: fstype not built into kernel,
			 * skip this iter and try a different one next
			 * time. */
			if (errno == EPERM) {
				ns_unsupported = true;
				(void)rmdir(path);
				return true;
			}
			(void)rmdir(path);
			continue;
		}

		__atomic_add_fetch(&shm->stats.mount_churn_mounts,
				   1, __ATOMIC_RELAXED);

		if (umount2(path, MNT_DETACH) == 0) {
			__atomic_add_fetch(&shm->stats.mount_churn_umounts,
					   1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&shm->stats.mount_churn_failed,
					   1, __ATOMIC_RELAXED);
			/* MNT_DETACH almost never fails for a freshly-
			 * created mount with no users, but if it does
			 * (EINVAL on a mount that vanished, EPERM on
			 * lockdown) leave the directory and move on —
			 * the next iteration uses a fresh name. */
		}

		(void)rmdir(path);
	}

	return true;
}
