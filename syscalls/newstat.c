/*
 * SYSCALL_DEFINE2(newstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include <limits.h>
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

static void sanitise_newstat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

/*
 * Oracle: newstat(filename, statbuf) is the symlink-following variant of
 * newlstat — stat() resolves the path through any intermediate symlinks
 * and writes the inode metadata of the *target* into the user struct stat.
 * For the resolved target, every inode-attribute field is byte-stable
 * across the ~150ms window between the original syscall return and our
 * post-hook re-call: st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid,
 * st_rdev, st_size, st_blksize, st_blocks all live on the inode and only
 * change via chmod / chown / link / truncate / unlink-and-replace on the
 * resolved target.  st_atim/st_mtim/st_ctim are excluded from the compare:
 * because stat() follows the symlink, atim on the resolved target can
 * legitimately advance if a sibling reads through the same path between
 * our two calls (read updates atim), and mtim/ctim can advance under a
 * sibling chmod/chown/write.  Excluding the three timestamps keeps the
 * false-positive rate near zero.  A divergence in the remaining ten
 * fields is not benign drift; it points at one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct stat in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - 32-bit-on-64-bit compat sign-extension of st_size, st_dev, or
 *     st_rdev (e.g. a small positive size sign-extending to 0xFFFF...).
 *   - struct-layout mismatch shifting st_dev into the st_ino slot, or
 *     st_blocks into st_blksize, on a kernel/glibc skew.
 *   - sibling-thread scribble of the user receive buffer between syscall
 *     return and our post-hook re-read.
 *
 * TOCTOU defeat (two buffers worth of it): both the input pathname and
 * the output stat buffer are user memory and a sibling can scribble
 * either between original return and re-issue.  The pathname is the
 * dominant attack surface — alloc_shared can hand it to another child
 * which then scribbles it; if we re-call with whatever rec->a1 holds
 * by then we may resolve a different file (or a different symlink target),
 * get different inode metadata, and report a false divergence.  Snapshot
 * BOTH the path (PATH_MAX stack buffer) and the original stat result
 * before the re-call.  If the re-call fails, give up rather than report.
 * Compare each field individually with no early-return so multi-field
 * corruption surfaces in a single sample, but bump the anomaly counter
 * only once per sample.  Sample one in a hundred to stay in line with
 * the rest of the oracle family and complement the just-landed newlstat
 * oracle.
 */
static void post_newstat(struct syscallrecord *rec)
{
	struct stat first, recheck;
	char local_path[PATH_MAX];
	int diverged = 0;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 == 0 || rec->a2 == 0)
		return;

	{
		void *buf = (void *)(unsigned long) rec->a2;
		void *path = (void *)(unsigned long) rec->a1;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a2/a1. */
		if (looks_like_corrupted_ptr(buf) || looks_like_corrupted_ptr(path)) {
			outputerr("post_newstat: rejected suspicious statbuf=%p filename=%p (pid-scribbled?)\n",
				  buf, path);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&first, (void *)(unsigned long) rec->a2, sizeof(first));
	strncpy(local_path, (const char *)(unsigned long) rec->a1, PATH_MAX - 1);
	local_path[PATH_MAX - 1] = '\0';

	if (syscall(SYS_stat, local_path, &recheck) != 0)
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
	       "newstat oracle anomaly: path=%s "
	       "first={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld} "
	       "recall={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld}\n",
	       local_path,
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

	__atomic_add_fetch(&shm->stats.newstat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);
}

struct syscallentry syscall_newstat = {
	.name = "newstat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_newstat,
	.post = post_newstat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
