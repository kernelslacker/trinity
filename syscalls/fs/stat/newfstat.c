/*
 * SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
 */
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "arch.h"
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two newfstat input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot retarget the re-issue at a
 * different fd or redirect the source memcpy at a foreign user buffer.
 */
#define NEWFSTAT_POST_STATE_MAGIC	0x4E465354UL	/* "NFST" */
struct newfstat_post_state {
	unsigned long magic;
	unsigned long fd;
	unsigned long statbuf;
	/*
	 * Seed for the poison pattern stamped into statbuf at sanitise
	 * time.  Returned by poison_output_struct() and fed back into
	 * check_output_struct() in the post handler so a stomp of
	 * rec->aN cannot redirect the check against an unrelated heap
	 * page that happens to still carry the original (or any) byte
	 * pattern.
	 */
	uint64_t poison_seed;
};

static void sanitise_newfstat(struct syscallrecord *rec)
{
	struct newfstat_post_state *snap;

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, page_size);

	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * statbuf pointer, so the source memcpy would touch a foreign
	 * allocation, and a stomped fd would silently steer the re-issue
	 * against a different inode entirely.  post_state is private to
	 * the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic   = NEWFSTAT_POST_STATE_MAGIC;
	snap->fd      = rec->a1;
	snap->statbuf = rec->a2;
	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler asks check_output_struct()
	 * whether the pattern survived intact; if it did on a success
	 * return, the kernel wrote zero bytes despite reporting success.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see (the relocation may have
	 * swapped rec->a2 for a fresh page).
	 */
	snap->poison_seed = poison_output_struct((void *)(unsigned long) rec->a2,
						 sizeof(struct stat), 0);
	post_state_install(rec, snap);
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
	struct newfstat_post_state *snap;
	struct stat first, recheck;
	int fd;
	int diverged = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, NEWFSTAT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (!ONE_IN(100))
		goto out_release;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->statbuf == 0)
		goto out_release;

	fd = (int) snap->fd;

	/*
	 * Untouched-buffer check: newfstat returned 0 (success) but the
	 * user buffer still byte-for-byte matches the poison pattern we
	 * stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all.  Bump the headline counter and let the
	 * field-level oracle below run as before; that will also fire
	 * (every field "differs" because first is all poison and recheck
	 * is real) but the dedicated counter is the cheaper, no-re-issue
	 * signal.
	 */
	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->statbuf,
					     sizeof(struct stat),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(first)))
		goto out_release;

	if (syscall(SYS_fstat, fd, &recheck) != 0)
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

	__atomic_add_fetch(&shm->stats.oracle.newfstat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_newfstat = {
	.name = "newfstat",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_STRUCT_PTR_OUT },
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
#include <limits.h>

#include "kernel/fcntl.h"
static unsigned long newfstatat_flags[] = {
	0,	/* no flags — follow symlinks (default behavior) */
	AT_SYMLINK_NOFOLLOW,
	AT_EMPTY_PATH,
	AT_NO_AUTOMOUNT,
};

/*
 * Snapshot of the four newfstatat input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a
 * sibling syscall scribbling rec->aN between the syscall returning
 * and the post handler running cannot redirect the oracle at a foreign
 * user buffer and cannot smear the dfd or the AT_* flag word that
 * steers lookup semantics on the re-issue.  The pathname is snapshotted
 * by VALUE into the embedded byte buffer below rather than by pointer
 * -- a stale heap-shaped pathname pointer that survived
 * looks_like_corrupted_ptr's shape-only gate would otherwise let the
 * .post strncpy walk off the end of an unrelated allocation, and a
 * sibling rewrite of the bytes between sanitise and post would forge
 * a clean-looking divergence.
 */
#define NEWFSTATAT_POST_STATE_MAGIC	0x4E465441UL	/* "NFTA" */
struct newfstatat_post_state {
	unsigned long magic;
	unsigned long dfd;
	unsigned long statbuf;
	unsigned long at_flags;
	char pathname[PATH_MAX];
	/*
	 * Seed for the poison pattern stamped into statbuf at sanitise
	 * time.  Returned by poison_output_struct() and fed back into
	 * check_output_struct() in the post handler so a stomp of
	 * rec->aN cannot redirect the check against an unrelated heap
	 * page that happens to still carry the original (or any) byte
	 * pattern.
	 */
	uint64_t poison_seed;
};

static void sanitise_newfstatat(struct syscallrecord *rec)
{
	struct newfstatat_post_state *snap;

	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a3, page_size);

	/*
	 * Snapshot input state for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original user buffer
	 * pointer, so the source memcpy would touch a foreign allocation,
	 * and a stomped dfd, flag word, or rec->a2 / sibling-rewritten
	 * pathname bytes would silently steer the re-call at a different
	 * inode than the one the original syscall actually resolved.
	 * Snapshot the pathname BYTES via post_snapshot_str so the post
	 * handler never re-derefs the user pointer; skip the post sample
	 * when the snapshot source is not provably readable.  post_state
	 * is private to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = NEWFSTATAT_POST_STATE_MAGIC;
	snap->dfd      = rec->a1;
	snap->statbuf  = rec->a3;
	snap->at_flags = rec->a4;
	if (!post_snapshot_str(snap->pathname, sizeof(snap->pathname),
			       (const char *)(unsigned long) rec->a2))
		snap->pathname[0] = '\0';
	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler asks check_output_struct()
	 * whether the pattern survived intact; if it did on a success
	 * return, the kernel wrote zero bytes despite reporting success.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see (the relocation may have
	 * swapped rec->a3 for a fresh page).
	 */
	snap->poison_seed = poison_output_struct((void *)(unsigned long) rec->a3,
						 sizeof(struct stat), 0);
	post_state_install(rec, snap);
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
	struct newfstatat_post_state *snap;
	struct stat first, recheck;
	int dfd, flag;
	int diverged = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, NEWFSTATAT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (!ONE_IN(100))
		goto out_release;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->statbuf == 0)
		goto out_release;

	if (snap->pathname[0] == '\0')
		goto out_release;

	dfd = (int) snap->dfd;

	flag = (int) snap->at_flags;

	/*
	 * Untouched-buffer check: newfstatat returned 0 (success) but the
	 * user buffer still byte-for-byte matches the poison pattern we
	 * stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all.  Bump the headline counter and let the
	 * field-level oracle below run as before; that will also fire
	 * (every field "differs" because first is all poison and recheck
	 * is real) but the dedicated counter is the cheaper, no-re-issue
	 * signal.
	 */
	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->statbuf,
					     sizeof(struct stat),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!post_snapshot_or_skip(&first,
				   (void *)(unsigned long) snap->statbuf,
				   sizeof(first)))
		goto out_release;

	if (syscall(SYS_newfstatat, dfd, snap->pathname, &recheck, flag) != 0)
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
	       "newfstatat oracle anomaly: dfd=%d path=%s flag=%x "
	       "first={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld} "
	       "recall={dev=%lx,ino=%lu,mode=%o,nlink=%lu,uid=%u,gid=%u,"
	       "rdev=%lx,size=%lld,blksize=%ld,blocks=%lld}\n",
	       dfd, snap->pathname, (unsigned int) flag,
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

	__atomic_add_fetch(&shm->stats.oracle.newfstatat_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
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
