/*
 * SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
 */
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_newfstat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

/*
 * Oracle: newfstat(fd, statbuf) writes the inode metadata of whatever
 * file the fd already names into the user struct stat.  The fd-based
 * variant of the stat-family oracle is the simplest of the bunch — the
 * descriptor itself names the inode, so there is no path string to
 * snapshot and no name-resolution TOCTOU window for a sibling to widen
 * by scribbling user memory between original return and re-call.
 *
 * The same ten inode-attribute fields that newlstat / newstat compare
 * are byte-stable across the ~150ms re-call window absent chmod / chown
 * / link / truncate / unlink-and-replace on the underlying inode:
 * st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, st_rdev, st_size,
 * st_blksize, st_blocks.  Timestamps (st_atim, st_mtim, st_ctim) are
 * deliberately excluded — sibling read / write / chmod on the same
 * inode legitimately advances them, and including them would dwarf any
 * real signal in benign drift.  A divergence in the remaining ten
 * fields points at one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct stat in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - struct-layout shift on a kernel/glibc skew that lands st_dev in
 *     the st_ino slot, or st_blocks in st_blksize.
 *   - 32-bit-on-64-bit compat sign-extension of st_size, st_dev, or
 *     st_rdev (e.g. a small positive size sign-extending to 0xFFFF...).
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *
 * The only benign-divergence path is a sibling closing the fd between
 * the original syscall and the recheck — that just makes the recheck
 * fail with -EBADF.  Treat any non-zero return from syscall(SYS_fstat)
 * as "give up, sample skipped" so we never report on a torn-down fd.
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family; compare each field individually with no early-return so
 * multi-field corruption surfaces in a single sample, but bump the
 * anomaly counter only once per sample.
 */
static void post_newfstat(struct syscallrecord *rec)
{
	struct stat first, recheck;
	int fd;
	int diverged = 0;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a2 == 0)
		return;

	fd = (int) rec->a1;

	{
		void *buf = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a2. */
		if (looks_like_corrupted_ptr(buf)) {
			outputerr("post_newfstat: rejected suspicious statbuf=%p (pid-scribbled?)\n",
				  buf);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&first, (void *)(unsigned long) rec->a2, sizeof(first));

	if (syscall(SYS_fstat, fd, &recheck) != 0)
		return;

	if (first.st_dev     != recheck.st_dev)     diverged = 1;
	if (first.st_ino     != recheck.st_ino)     diverged = 1;
	if (first.st_mode    != recheck.st_mode)    diverged = 1;
	if (first.st_nlink   != recheck.st_nlink)   diverged = 1;
	if (first.st_uid     != recheck.st_uid)     diverged = 1;
	if (first.st_gid     != recheck.st_gid)     diverged = 1;
	if (first.st_rdev    != recheck.st_rdev)    diverged = 1;
	if (first.st_size    != recheck.st_size)    diverged = 1;
	if (first.st_blksize != recheck.st_blksize) diverged = 1;
	if (first.st_blocks  != recheck.st_blocks)  diverged = 1;

	if (!diverged)
		return;

	output(0,
	       "newfstat oracle anomaly: fd=%d "
	       "first={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld} "
	       "recall={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld}\n",
	       fd,
	       (unsigned long) first.st_dev, (unsigned long) first.st_ino,
	       (unsigned int) first.st_mode, (unsigned long) first.st_nlink,
	       (unsigned int) first.st_uid, (unsigned int) first.st_gid,
	       (unsigned long) first.st_rdev, (long long) first.st_size,
	       (long) first.st_blksize, (long long) first.st_blocks,
	       (unsigned long) recheck.st_dev, (unsigned long) recheck.st_ino,
	       (unsigned int) recheck.st_mode, (unsigned long) recheck.st_nlink,
	       (unsigned int) recheck.st_uid, (unsigned int) recheck.st_gid,
	       (unsigned long) recheck.st_rdev, (long long) recheck.st_size,
	       (long) recheck.st_blksize, (long long) recheck.st_blocks);

	__atomic_add_fetch(&shm->stats.newfstat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
}

struct syscallentry syscall_newfstat = {
	.name = "newfstat",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fd", [1] = "statbuf" },
	.sanitise = sanitise_newfstat,
	.post = post_newfstat,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};


/*
 * SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
                   struct stat __user *, statbuf, int, flag)
 */
#include <fcntl.h>
#include <limits.h>

static unsigned long newfstatat_flags[] = {
	0,	/* no flags — follow symlinks (default behavior) */
	AT_SYMLINK_NOFOLLOW,
	AT_EMPTY_PATH,
	AT_NO_AUTOMOUNT,
};

static void sanitise_newfstatat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a3, page_size);
}

/*
 * Oracle: newfstatat(dfd, pathname, statbuf, flag) is the path-based
 * sibling of fstatat — it resolves pathname relative to dfd (or the cwd
 * when dfd == AT_FDCWD) and writes the inode metadata of the resulting
 * dentry into the user struct stat.  The flag argument selects the
 * resolution semantics: AT_SYMLINK_NOFOLLOW gives lstat-equivalent
 * behavior on the final component, AT_EMPTY_PATH lets an empty pathname
 * stat the dfd itself, and AT_NO_AUTOMOUNT suppresses automounter
 * triggering.  All four args must be snapshotted before the re-issue
 * because each one steers the lookup to a different inode.
 *
 * The same ten inode-attribute fields used by newfstat / newlstat /
 * newstat are byte-stable across the ~150ms re-call window absent
 * chmod / chown / link / truncate / unlink-and-replace on the underlying
 * inode: st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, st_rdev,
 * st_size, st_blksize, st_blocks.  Timestamps (st_atim, st_mtim, st_ctim)
 * are excluded — sibling read / write / chmod legitimately advances
 * them.  A divergence in the remaining ten fields is not benign drift;
 * it points at one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct stat in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - 32-bit-on-64-bit compat sign-extension of st_size, st_dev, or
 *     st_rdev (e.g. a small positive size sign-extending to 0xFFFF...).
 *   - struct-layout mismatch shifting st_dev into the st_ino slot, or
 *     st_blocks into st_blksize, on a kernel/glibc skew.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - sibling-thread rename / replace of the path component between the
 *     original lookup and the recheck (caught only because we resolved
 *     the snapshotted path and got a different inode).
 *
 * TOCTOU defeat (three buffers worth of it): pathname, statbuf, and
 * flag are all reachable from sibling-scribbleable user memory or
 * shared bookkeeping.  Snapshot the dfd, the path (PATH_MAX stack
 * buffer), the flag word, and the original stat result before re-issue.
 * Switching the flag bits between calls would change lookup semantics
 * (NOFOLLOW vs follow on the last component) and produce a benign
 * "different inode" divergence that is purely an artifact of our own
 * race window — preserving the original flag eliminates that source.
 *
 * If the recheck syscall itself fails, a sibling has closed the dfd,
 * unlinked the path, or scribbled the statbuf into an unmapped region;
 * all benign.  Treat any non-zero return from syscall(SYS_newfstatat)
 * as "give up, sample skipped" so we never report on a torn-down path
 * or descriptor.  Sample one in a hundred to stay in line with the
 * rest of the oracle family; compare each field individually with no
 * early-return so multi-field corruption surfaces in a single sample,
 * but bump the anomaly counter only once per sample.
 */
static void post_newfstatat(struct syscallrecord *rec)
{
	struct stat first, recheck;
	char local_path[PATH_MAX];
	int dfd, flag;
	int diverged = 0;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a2 == 0 || rec->a3 == 0)
		return;

	dfd = (int) rec->a1;

	{
		void *buf = (void *)(unsigned long) rec->a3;
		void *path = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a3/a2. */
		if (looks_like_corrupted_ptr(buf) || looks_like_corrupted_ptr(path)) {
			outputerr("post_newfstatat: rejected suspicious statbuf=%p filename=%p (pid-scribbled?)\n",
				  buf, path);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	strncpy(local_path, (const char *)(unsigned long) rec->a2, PATH_MAX - 1);
	local_path[PATH_MAX - 1] = '\0';
	flag = (int) rec->a4;
	memcpy(&first, (void *)(unsigned long) rec->a3, sizeof(first));

	if (syscall(SYS_newfstatat, dfd, local_path, &recheck, flag) != 0)
		return;

	if (first.st_dev     != recheck.st_dev)     diverged = 1;
	if (first.st_ino     != recheck.st_ino)     diverged = 1;
	if (first.st_mode    != recheck.st_mode)    diverged = 1;
	if (first.st_nlink   != recheck.st_nlink)   diverged = 1;
	if (first.st_uid     != recheck.st_uid)     diverged = 1;
	if (first.st_gid     != recheck.st_gid)     diverged = 1;
	if (first.st_rdev    != recheck.st_rdev)    diverged = 1;
	if (first.st_size    != recheck.st_size)    diverged = 1;
	if (first.st_blksize != recheck.st_blksize) diverged = 1;
	if (first.st_blocks  != recheck.st_blocks)  diverged = 1;

	if (!diverged)
		return;

	output(0,
	       "newfstatat oracle anomaly: dfd=%d path=%s flag=%x "
	       "first={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld} "
	       "recall={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld}\n",
	       dfd, local_path, (unsigned int) flag,
	       (unsigned long) first.st_dev, (unsigned long) first.st_ino,
	       (unsigned int) first.st_mode, (unsigned long) first.st_nlink,
	       (unsigned int) first.st_uid, (unsigned int) first.st_gid,
	       (unsigned long) first.st_rdev, (long long) first.st_size,
	       (long) first.st_blksize, (long long) first.st_blocks,
	       (unsigned long) recheck.st_dev, (unsigned long) recheck.st_ino,
	       (unsigned int) recheck.st_mode, (unsigned long) recheck.st_nlink,
	       (unsigned int) recheck.st_uid, (unsigned int) recheck.st_gid,
	       (unsigned long) recheck.st_rdev, (long long) recheck.st_size,
	       (long) recheck.st_blksize, (long long) recheck.st_blocks);

	__atomic_add_fetch(&shm->stats.newfstatat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
}

struct syscallentry syscall_newfstatat = {
	.name = "newfstatat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "statbuf", [3] = "flag" },
	.arg_params[3].list = ARGLIST(newfstatat_flags),
	.sanitise = sanitise_newfstatat,
	.post = post_newfstatat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
