/*
 * SYSCALL_DEFINE2(newlstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include <limits.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "arch.h"
#include "output-poison.h"
#include "pathnames.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, utime, stat, lstat, statfs, ...) touch;
 * cross-process contention concentrates on the same per-inode i_rwsem /
 * getattr path.
 */
#define NR_TESTFILES 4

/*
 * Snapshot of the two newlstat input args plus the poison seed read by
 * the post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot steer the source memcpy
 * at a foreign user statbuf or smear the poison seed against a heap
 * page that happens to still carry a residual pattern from an earlier
 * call.  The pathname is snapshotted by VALUE into the embedded byte
 * buffer below rather than by pointer -- a stale heap-shaped filename
 * pointer that survived looks_like_corrupted_ptr's shape-only gate would
 * otherwise let the .post strncpy walk off the end of an unrelated
 * allocation, and a sibling rewrite of the bytes between sanitise and
 * post would forge a clean-looking divergence.  A poison_seed of 0
 * means the sanitise-time writability check refused to stamp poison
 * for this call and the post handler must no-op the untouched-buffer
 * check.
 */
#define NEWLSTAT_POST_STATE_MAGIC	0x4E4C5354UL	/* "NLST" */
struct newlstat_post_state {
	unsigned long magic;
	unsigned long statbuf;
	uint64_t poison_seed;
	char filename[PATH_MAX];
};

static void sanitise_newlstat(struct syscallrecord *rec)
{
	struct newlstat_post_state *snap;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
	 * random path is most often not a real file at all -- newlstat
	 * returns ENOENT at the path walk before ever reaching the
	 * per-fs inode_operations->getattr path under i_rwsem.  Same
	 * "high calls, low edges" cold-syscall shape stat / lstat /
	 * statfs were in before their testfile-pin fixes.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths so the subsequent newlstat lands on a real
	 * trinity-owned inode and penetrates the VFS path -- the namei
	 * walk to a real dentry, the permission check (trinity owns
	 * these inodes so the ownership/permission gates pass), and the
	 * per-fs getattr that the i_rwsem guards.  The other half
	 * preserves the slot exactly as the generic draw left it, so the
	 * ENOENT reject arm stays exercised.
	 *
	 * Done as an if-block rather than an early-return so the existing
	 * rec->post_state init, avoid_shared_buffer_out(&rec->a2) and the
	 * post_state snapshot below still run on both halves -- the path
	 * pin is purely additive to the existing a2 / post-oracle work.
	 * Placed before the snapshot so the snapshot captures the pinned
	 * filename and the post oracle re-issues against the same path
	 * the original syscall walked.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL)
			rec->a1 = (unsigned long) path;
	}

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * Snapshot input state for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original user
	 * statbuf pointer, so the source memcpy would touch a foreign
	 * allocation, and a stale rec->a1 / sibling-rewritten pathname
	 * bytes would let the re-issue resolve a different symlink
	 * entirely.  Snapshot the filename BYTES via post_snapshot_str so
	 * the post handler never re-derefs the user pointer; skip the
	 * post sample entirely when the snapshot source is not provably
	 * readable.  post_state is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = NEWLSTAT_POST_STATE_MAGIC;
	snap->statbuf  = rec->a2;
	if (!post_snapshot_str(snap->filename, sizeof(snap->filename),
			       (const char *)(unsigned long) rec->a1))
		snap->filename[0] = '\0';
	/*
	 * Stamp a per-call poison pattern into the user struct stat the
	 * kernel is about to fill.  The post handler feeds the seed back
	 * into check_output_struct(); a byte-identical poison after a
	 * retval == 0 return means the kernel skipped copy_to_user()
	 * entirely -- newlstat(2) contracts to overwrite the whole
	 * struct stat on success via cp_new_stat().  Gate on
	 * range_readable_user() so a writable-pool draw that
	 * avoid_shared_buffer_out() moved to an address that is no
	 * longer provably mapped -- e.g. a sibling munmap between
	 * allocation and now -- does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk.  On skip, poison_seed stays
	 * 0 and the post handler no-ops the poison check while the
	 * field-diff oracle still runs against snap->statbuf.  Done
	 * after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see.
	 */
	{
		void *buf = (void *)(unsigned long) rec->a2;

		if (range_readable_user(buf, sizeof(struct stat)))
			snap->poison_seed = poison_output_struct(buf,
								 sizeof(struct stat),
								 0);
	}
	post_state_install(rec, snap);
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
	struct newlstat_post_state *snap;
	struct stat first, recheck;
	int diverged = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, NEWLSTAT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->statbuf == 0)
		goto out_release;

	/*
	 * Untouched-buffer check: newlstat returned 0 (success) but the
	 * user struct stat still byte-for-byte matches the poison
	 * pattern we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all.  Runs on every success (no ONE_IN gate)
	 * because the check is a ~sizeof(struct stat) memcmp with no
	 * re-issue, so it stays cheap enough to fire every time; bumps
	 * the shared post_handler_untouched_out_buf slot.  Skip when
	 * poison_seed is 0: sanitise refused to stamp (unmapped
	 * statbuf) so there is no pattern to compare against.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->statbuf,
					     sizeof(struct stat),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	if (snap->filename[0] == '\0')
		goto out_release;

	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(first)))
		goto out_release;

	if (syscall(SYS_newfstatat, AT_FDCWD, snap->filename, &recheck,
		    AT_SYMLINK_NOFOLLOW) != 0)
		goto out_release;

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
		goto out_release;

	output(0,
	       "newlstat oracle anomaly: path=%s "
	       "first={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld} "
	       "recall={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld}\n",
	       snap->filename,
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

	__atomic_add_fetch(&shm->stats.oracle.newlstat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
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
	.flags = REEXEC_SANITISE_OK,
};
