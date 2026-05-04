/*
 * SYSCALL_DEFINE2(newstat, const char __user *, filename, struct stat __user *, statbuf)
 */
#include <fcntl.h>
#include <limits.h>
#include <linux/stat.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_statbuf_a2(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, page_size);
}

struct syscallentry syscall_stat = {
	.name = "stat",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_statbuf_a2,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE2(stat64, const char __user *, filename, struct stat64 __user *, statbuf)
 */

struct syscallentry syscall_stat64 = {
	.name = "stat64",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "filename", [1] = "statbuf" },
	.sanitise = sanitise_statbuf_a2,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE5(statx, int, dfd, const char __user *, filename, unsigned, flags, unsigned int, mask, struct statx __user *, buffer)
 */

#define AT_STATX_SYNC_TYPE      0x6000  /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT   0x0000  /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC     0x2000  /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC      0x4000  /* - Don't sync attributes with the server */

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW     0x100   /* Do not follow symbolic links */
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT         0x800   /* Suppress terminal automount traversal */
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH           0x1000  /* Allow empty relative pathname (resolve dfd alone) */
#endif

static unsigned long statx_flags[] = {
	AT_STATX_SYNC_TYPE, AT_STATX_SYNC_AS_STAT, AT_STATX_FORCE_SYNC, AT_STATX_DONT_SYNC,
	AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH,
};

#ifndef STATX_TYPE
#define STATX_TYPE		0x00000001
#define STATX_MODE		0x00000002
#define STATX_NLINK		0x00000004
#define STATX_UID		0x00000008
#define STATX_GID		0x00000010
#define STATX_ATIME		0x00000020
#define STATX_MTIME		0x00000040
#define STATX_CTIME		0x00000080
#define STATX_INO		0x00000100
#define STATX_SIZE		0x00000200
#define STATX_BLOCKS		0x00000400
#define STATX_BTIME		0x00000800
#define STATX_MNT_ID		0x00001000
#define STATX_DIOALIGN		0x00002000
#define STATX_MNT_ID_UNIQUE	0x00004000
#define STATX_SUBVOL		0x00008000
#endif

/*
 * Per-bit guards: STATX_WRITE_ATOMIC landed in 6.11 and STATX_DIO_READ_ALIGN
 * in 6.13, after the umbrella STATX_TYPE block above was last refreshed.  A
 * uapi snapshot from 6.10..6.12 defines STATX_TYPE (skipping the block above)
 * but is missing one or both of these.  Guarding individually fills the gap
 * without redefining bits the host header already provides.
 */
#ifndef STATX_WRITE_ATOMIC
#define STATX_WRITE_ATOMIC	0x00010000
#endif
#ifndef STATX_DIO_READ_ALIGN
#define STATX_DIO_READ_ALIGN	0x00020000
#endif

static unsigned long statx_mask[] = {
	STATX_TYPE, STATX_MODE, STATX_NLINK, STATX_UID, STATX_GID,
	STATX_ATIME, STATX_MTIME, STATX_CTIME, STATX_INO, STATX_SIZE,
	STATX_BLOCKS, STATX_BTIME, STATX_MNT_ID, STATX_DIOALIGN,
	STATX_MNT_ID_UNIQUE, STATX_SUBVOL, STATX_WRITE_ATOMIC,
	STATX_DIO_READ_ALIGN,
};

/*
 * Snapshot of the five statx input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign pathname or statxbuf,
 * cannot flip the dfd, and cannot smear the lookup flags or the field-
 * select mask used to seed the re-issue.
 */
struct statx_post_state {
	unsigned long dfd;
	unsigned long pathname;
	unsigned long flags;
	unsigned long mask;
	unsigned long statxbuf;
};

static void sanitise_statx(struct syscallrecord *rec)
{
	struct statx_post_state *snap;

	rec->post_state = 0;

	avoid_shared_buffer(&rec->a5, page_size);

	/*
	 * Snapshot the five input args for the post oracle.  Without this
	 * the post handler reads rec->a1..a5 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * pathname or statxbuf pointers, so the strncpy / memcpy / re-issue
	 * would touch a foreign allocation, and a stomped flags or mask
	 * word would change the lookup semantics or the bits the kernel
	 * sets in stx_mask and break the intersection logic on the
	 * re-issue.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->dfd      = rec->a1;
	snap->pathname = rec->a2;
	snap->flags    = rec->a3;
	snap->mask     = rec->a4;
	snap->statxbuf = rec->a5;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: statx(dfd, pathname, flags, mask, statxbuf) is the modern
 * path-based stat — it resolves pathname relative to dfd, applies the
 * lookup flags (AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH,
 * AT_STATX_SYNC_*), and fills only those struct statx fields the caller
 * asked for in mask AND that the underlying filesystem actually supports.
 * The reply's stx_mask reports which fields are valid; everything else
 * in the buffer is undefined.  All five args steer either name resolution
 * or which fields the kernel writes, so all five must be snapshotted
 * before the re-issue.
 *
 * Mask intersection wrinkle: comparing a field that the original call
 * filled but the recheck did not (or vice versa) would false-positive
 * on transient mask differences — a filesystem that lazily computes
 * STATX_BLOCKS, a btrfs subvolume crossing, a recheck arriving before
 * STATX_BTIME has been read off disk.  Compare only fields whose bit
 * is set in BOTH stx_masks: valid_mask = first.stx_mask & recheck.stx_mask.
 *
 * Mask-gated fields (compare iff valid_mask has the bit):
 *   STATX_TYPE | STATX_MODE   stx_mode (one __u16, fed by either bit)
 *   STATX_NLINK              stx_nlink
 *   STATX_UID                stx_uid
 *   STATX_GID                stx_gid
 *   STATX_INO                stx_ino
 *   STATX_SIZE               stx_size
 *   STATX_BLOCKS             stx_blocks
 *
 * Always-on fields (kernel fills unconditionally per the UAPI):
 *   stx_blksize, stx_dev_major+stx_dev_minor, stx_rdev_major+stx_rdev_minor
 *
 * Excluded (would drift legitimately or carry no inode-stable signal):
 *   stx_atime / stx_mtime / stx_ctime / stx_btime — sibling read / write /
 *     chmod legitimately advances these.
 *   stx_attributes / stx_attributes_mask — file-attribute flags can
 *     legitimately flip (chattr +i, FS_DAX_FL toggle, FS_VERITY_FL set).
 *   stx_mnt_id — bind-mount churn / mount propagation across a private
 *     namespace can change this without the inode changing.
 *   stx_dio_mem_align / stx_dio_offset_align / stx_dio_read_offset_align /
 *     stx_subvol / stx_atomic_write_* — rare reconfiguration paths that
 *     legitimately change without the underlying inode rotating.
 *
 * A divergence in the compared fields is not benign drift; it points
 * at one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct statx in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - struct-layout shift on a kernel/glibc skew that lands stx_ino in
 *     the stx_size slot, or stx_blocks in stx_blksize.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - sibling-thread rename / replace of the path component between the
 *     original lookup and the recheck (caught only because we resolved
 *     the snapshotted path and got a different inode).
 *
 * TOCTOU defeat (five buffers worth of it): pathname, flags, mask, and
 * statxbuf are all reachable from sibling-scribbleable user memory or
 * shared bookkeeping.  The five input args (dfd, pathname, flags, mask,
 * statxbuf) are snapshotted at sanitise time into a heap struct in
 * rec->post_state, so a sibling that scribbles rec->aN between syscall
 * return and post entry cannot retarget the dfd, redirect the strncpy
 * at a foreign pathname, smear the flags or mask used to seed the
 * re-issue, or steer the memcpy at a foreign statxbuf.  We still copy
 * the path into a PATH_MAX stack buffer and the original statx result
 * into a stack-local before re-issuing, so a sibling that scribbles the
 * user buffers themselves between the two reads cannot smear the
 * comparison.  Switching flags between calls would change lookup
 * semantics (NOFOLLOW vs follow, sync mode) and produce a benign
 * "different inode" or "different field" divergence that is purely an
 * artifact of our own race window — preserving the snapshotted flags
 * eliminates that source.  The mask preservation matters too:
 * requesting different fields the second time would shift which bits
 * the kernel sets in stx_mask and break the intersection logic.
 *
 * If the recheck syscall itself fails, a sibling has closed the dfd,
 * unlinked the path, or scribbled the statxbuf into an unmapped region;
 * all benign.  Treat any non-zero return from syscall(SYS_statx) as
 * "give up, sample skipped" so we never report on a torn-down path or
 * descriptor.  Sample one in a hundred to stay in line with the rest of
 * the oracle family; compare each field individually with no early-return
 * so multi-field corruption surfaces in a single sample, but bump the
 * anomaly counter only once per sample.
 */
static void post_statx(struct syscallrecord *rec)
{
	struct statx_post_state *snap = (struct statx_post_state *) rec->post_state;
	struct statx first, recheck;
	char local_path[PATH_MAX];
	unsigned int flags, mask, valid_mask;
	int dfd;
	int diverged = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_statx: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->pathname == 0 || snap->statxbuf == 0)
		goto out_free;

	dfd = (int) snap->dfd;

	{
		void *buf = (void *)(unsigned long) snap->statxbuf;
		void *path = (void *)(unsigned long) snap->pathname;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled statxbuf/pathname before deref.
		 */
		if (looks_like_corrupted_ptr(rec, buf) || looks_like_corrupted_ptr(rec, path)) {
			outputerr("post_statx: rejected suspicious buffer=%p filename=%p (post_state-scribbled?)\n",
				  buf, path);
			goto out_free;
		}
	}

	strncpy(local_path, (const char *)(unsigned long) snap->pathname, PATH_MAX - 1);
	local_path[PATH_MAX - 1] = '\0';
	flags = (unsigned int) snap->flags;
	mask = (unsigned int) snap->mask;
	memcpy(&first, (void *)(unsigned long) snap->statxbuf, sizeof(first));

	if (syscall(SYS_statx, dfd, local_path, flags, mask, &recheck) != 0)
		goto out_free;

	valid_mask = first.stx_mask & recheck.stx_mask;

	if (valid_mask & (STATX_TYPE | STATX_MODE))
		if (first.stx_mode != recheck.stx_mode) diverged = 1;
	if (valid_mask & STATX_NLINK)
		if (first.stx_nlink != recheck.stx_nlink) diverged = 1;
	if (valid_mask & STATX_UID)
		if (first.stx_uid != recheck.stx_uid) diverged = 1;
	if (valid_mask & STATX_GID)
		if (first.stx_gid != recheck.stx_gid) diverged = 1;
	if (valid_mask & STATX_INO)
		if (first.stx_ino != recheck.stx_ino) diverged = 1;
	if (valid_mask & STATX_SIZE)
		if (first.stx_size != recheck.stx_size) diverged = 1;
	if (valid_mask & STATX_BLOCKS)
		if (first.stx_blocks != recheck.stx_blocks) diverged = 1;

	if (first.stx_blksize    != recheck.stx_blksize)    diverged = 1;
	if (first.stx_dev_major  != recheck.stx_dev_major)  diverged = 1;
	if (first.stx_dev_minor  != recheck.stx_dev_minor)  diverged = 1;
	if (first.stx_rdev_major != recheck.stx_rdev_major) diverged = 1;
	if (first.stx_rdev_minor != recheck.stx_rdev_minor) diverged = 1;

	if (!diverged)
		goto out_free;

	output(0,
	       "statx oracle anomaly: dfd=%d path=%s flags=%x mask=%x valid_mask=%x "
	       "first={mask=%x,mode=%o,nlink=%u,uid=%u,gid=%u,ino=%llu,size=%llu,"
	       "blocks=%llu,blksize=%u,dev=%u:%u,rdev=%u:%u} "
	       "recall={mask=%x,mode=%o,nlink=%u,uid=%u,gid=%u,ino=%llu,size=%llu,"
	       "blocks=%llu,blksize=%u,dev=%u:%u,rdev=%u:%u}\n",
	       dfd, local_path, flags, mask, valid_mask,
	       (unsigned int) first.stx_mask, (unsigned int) first.stx_mode,
	       (unsigned int) first.stx_nlink, (unsigned int) first.stx_uid,
	       (unsigned int) first.stx_gid,
	       (unsigned long long) first.stx_ino,
	       (unsigned long long) first.stx_size,
	       (unsigned long long) first.stx_blocks,
	       (unsigned int) first.stx_blksize,
	       (unsigned int) first.stx_dev_major, (unsigned int) first.stx_dev_minor,
	       (unsigned int) first.stx_rdev_major, (unsigned int) first.stx_rdev_minor,
	       (unsigned int) recheck.stx_mask, (unsigned int) recheck.stx_mode,
	       (unsigned int) recheck.stx_nlink, (unsigned int) recheck.stx_uid,
	       (unsigned int) recheck.stx_gid,
	       (unsigned long long) recheck.stx_ino,
	       (unsigned long long) recheck.stx_size,
	       (unsigned long long) recheck.stx_blocks,
	       (unsigned int) recheck.stx_blksize,
	       (unsigned int) recheck.stx_dev_major, (unsigned int) recheck.stx_dev_minor,
	       (unsigned int) recheck.stx_rdev_major, (unsigned int) recheck.stx_rdev_minor);

	__atomic_add_fetch(&shm->stats.statx_oracle_anomalies, 1,
			   __ATOMIC_RELAXED);

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_statx = {
	.name = "statx",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_LIST, [4] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags", [3] = "mask", [4] = "buffer" },
	.arg_params[2].list = ARGLIST(statx_flags),
	.arg_params[3].list = ARGLIST(statx_mask),
	.sanitise = sanitise_statx,
	.post = post_statx,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
};
