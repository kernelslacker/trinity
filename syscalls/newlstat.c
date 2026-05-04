/*
 * SYSCALL_DEFINE2(newlstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two newlstat input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect the strncpy at a
 * foreign pathname or steer the source memcpy at a foreign user
 * statbuf.
 */
struct newlstat_post_state {
	unsigned long filename;
	unsigned long statbuf;
};

static void sanitise_newlstat(struct syscallrecord *rec)
{
	struct newlstat_post_state *snap;

	rec->post_state = 0;

	avoid_shared_buffer(&rec->a2, page_size);

	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * pathname or statbuf pointers, so the strncpy / memcpy would touch
	 * a foreign allocation and the re-issue could resolve a different
	 * symlink entirely.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->filename = rec->a1;
	snap->statbuf  = rec->a2;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: newlstat(filename, statbuf) writes the inode metadata of the
 * symlink itself (lstat does not follow) into the user struct stat.
 * For a given symlink, every inode-attribute field is byte-stable across
 * the ~150ms window between the original syscall return and our post-hook
 * re-call: st_dev, st_ino, st_mode, st_nlink, st_uid, st_gid, st_rdev,
 * st_size, st_blksize, st_blocks all live on the inode and only change
 * via chmod / chown / link / truncate / unlink-and-replace on the path.
 * A sibling thread may legitimately touch the timestamps (atim/mtim/ctim
 * advance on access/modify/metadata-change), so those three are excluded
 * from the compare to keep false-positive rate near zero.  A divergence
 * in the remaining ten fields is not benign drift; it points at one of:
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
 * by then we may resolve a different file, get different inode metadata,
 * and report a false divergence.  Snapshot BOTH the path (PATH_MAX
 * stack buffer) and the original stat result before the re-call.  If
 * the re-call fails, give up rather than report.  Compare each field
 * individually with no early-return so multi-field corruption surfaces
 * in a single sample, but bump the anomaly counter only once per sample.
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.
 */
static void post_newlstat(struct syscallrecord *rec)
{
	struct newlstat_post_state *snap =
		(struct newlstat_post_state *) rec->post_state;
	struct stat first, recheck;
	char local_path[PATH_MAX];
	int diverged = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_newlstat: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->filename == 0 || snap->statbuf == 0)
		goto out_free;

	{
		void *buf = (void *)(unsigned long) snap->statbuf;
		void *path = (void *)(unsigned long) snap->filename;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner
		 * statbuf / filename fields.  Reject pid-scribbled pointers
		 * before deref.
		 */
		if (looks_like_corrupted_ptr(buf) || looks_like_corrupted_ptr(path)) {
			outputerr("post_newlstat: rejected suspicious statbuf=%p filename=%p (post_state-scribbled?)\n",
				  buf, path);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
					   __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	memcpy(&first, (void *)(unsigned long) snap->statbuf, sizeof(first));
	strncpy(local_path, (const char *)(unsigned long) snap->filename, PATH_MAX - 1);
	local_path[PATH_MAX - 1] = '\0';

	if (syscall(SYS_lstat, local_path, &recheck) != 0)
		goto out_free;

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
		goto out_free;

	output(0,
	       "newlstat oracle anomaly: path=%s "
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

	__atomic_add_fetch(&shm->stats.newlstat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_newlstat = {
	.name = "newlstat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_newlstat,
	.post = post_newlstat,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
