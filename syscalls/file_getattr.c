/*
 * SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,
 *		struct file_attr __user *, ufattr, size_t, usize,
 *		unsigned int, at_flags)
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

#if defined(SYS_file_getattr) || defined(__NR_file_getattr)
#ifndef SYS_file_getattr
#define SYS_file_getattr __NR_file_getattr
#endif
#define HAVE_SYS_FILE_GETATTR 1
#endif

static unsigned long file_getattr_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

#ifdef HAVE_SYS_FILE_GETATTR
/*
 * Snapshot of the five file_getattr input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign pathname or ufattr,
 * cannot flip the dfd, and cannot smear the usize bound or the at_flags
 * lookup mode used to seed the re-issue.
 */
struct file_getattr_post_state {
	unsigned long dfd;
	unsigned long pathname;
	unsigned long ufattr;
	unsigned long usize;
	unsigned long at_flags;
};
#endif

static void sanitise_file_getattr(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_FILE_GETATTR
	struct file_getattr_post_state *snap;

	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a3, rec->a4);

#ifdef HAVE_SYS_FILE_GETATTR
	/*
	 * Snapshot the five input args for the post oracle.  Without this
	 * the post handler reads rec->a1..a5 at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * pathname or ufattr pointers, so the strncpy / memcpy / re-issue
	 * would touch a foreign allocation, and a stomped usize or at_flags
	 * word would smear the comparison bound or change the lookup mode.
	 * post_state is private to the post handler.  Gated on
	 * HAVE_SYS_FILE_GETATTR to mirror the .post body -- on systems
	 * without SYS_file_getattr the post handler is a no-op stub and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->dfd      = rec->a1;
	snap->pathname = rec->a2;
	snap->ufattr   = rec->a3;
	snap->usize    = rec->a4;
	snap->at_flags = rec->a5;
	rec->post_state = (unsigned long) snap;
#endif
}

/*
 * Oracle: file_getattr(dfd, filename, ufattr, usize, at_flags) writes a
 * struct file_attr describing the inode's filesystem-attribute flags
 * (xflags: immutable, append, sync, no_atime, no_dump, ...; extsize;
 * project id; cow extsize; nextents) into the user buffer.  Every field
 * lives on the inode and is stable across the ~150ms window between the
 * original syscall return and our post-hook re-call -- the only legitimate
 * mutator is a chattr(1)/FS_IOC_FSSETXATTR-class operation, which a sibling
 * trinity child could fire but is rare enough that any divergence we see is
 * far more likely to be one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct file_attr in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - 32-bit-on-64-bit compat sign-extension on the size_t usize word.
 *   - struct-layout mismatch shifting fa_xflags into the fa_extsize slot,
 *     or fa_projid into fa_cowextsize, on a kernel/glibc skew.
 *   - sibling-thread scribble of the user receive buffer between syscall
 *     return and our post-hook re-read.
 *
 * TOCTOU defeat (five buffers worth of it): the dfd, pathname, ufattr,
 * usize, and at_flags args are snapshotted at sanitise time into a heap
 * struct in rec->post_state, so a sibling that scribbles rec->aN between
 * syscall return and post entry cannot retarget the dfd, redirect the
 * strncpy at a foreign pathname, steer the memcpy at a foreign ufattr,
 * smear the usize comparison bound, or flip at_flags between the
 * original lookup mode and the re-issue.  The pathname is the dominant
 * attack surface -- alloc_shared can hand it to another child which
 * then scribbles it; the snap captures the pointer the kernel actually
 * resolved on the original call.  We still copy the path into a
 * PATH_MAX stack buffer and the first usize bytes of the original
 * file_attr into a stack-local before re-calling, so a sibling that
 * scribbles the user buffers themselves between the two reads cannot
 * smear the comparison.  Re-issue with FRESH private buffers (do NOT
 * pass the snap's ufattr -- a sibling could mutate the user buffer
 * mid-syscall and forge a clean compare).  If the re-call fails, give
 * up rather than report (file may have been unlinked by sibling between
 * calls).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  A real chattr-race divergence is itself an interesting TOCTOU
 * we want to surface; the ONE_IN(100) sampling keeps signal alive without
 * flooding the channel.
 */
static void post_file_getattr(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_FILE_GETATTR
	struct file_getattr_post_state *snap =
		(struct file_getattr_post_state *) rec->post_state;
	struct file_attr first_attr;
	struct file_attr recheck_attr;
	char path_local[PATH_MAX];
	size_t usize;
	unsigned int at_flags;
	int dfd;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_file_getattr: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->pathname == 0 || snap->ufattr == 0)
		goto out_free;

	usize = (size_t) snap->usize;
	if (usize < sizeof(struct file_attr))
		goto out_free;
	if (usize > sizeof(struct file_attr))
		usize = sizeof(struct file_attr);

	dfd = (int) snap->dfd;
	at_flags = (unsigned int) snap->at_flags;

	{
		void *ufattr = (void *)(unsigned long) snap->ufattr;
		void *path = (void *)(unsigned long) snap->pathname;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled ufattr/pathname before deref.
		 */
		if (looks_like_corrupted_ptr(rec, ufattr) || looks_like_corrupted_ptr(rec, path)) {
			outputerr("post_file_getattr: rejected suspicious ufattr=%p filename=%p (post_state-scribbled?)\n",
				  ufattr, path);
			goto out_free;
		}
	}

	strncpy(path_local, (const char *) snap->pathname, PATH_MAX - 1);
	path_local[PATH_MAX - 1] = '\0';
	if (path_local[0] == '\0')
		goto out_free;

	memcpy(&first_attr, (const void *) snap->ufattr, usize);

	memset(&recheck_attr, 0, sizeof(recheck_attr));
	rc = syscall(SYS_file_getattr, dfd, path_local, &recheck_attr,
		     sizeof(recheck_attr), at_flags);
	if (rc != 0)
		goto out_free;

	if (memcmp(&first_attr, &recheck_attr, usize) != 0) {
		const unsigned char *first_bytes = (const unsigned char *) &first_attr;
		const unsigned char *recheck_bytes = (const unsigned char *) &recheck_attr;
		char first_hex[8 * 3 + 1];
		char recheck_hex[8 * 3 + 1];
		size_t off;
		unsigned int i;

		off = 0;
		for (i = 0; i < 8; i++)
			off += snprintf(first_hex + off, sizeof(first_hex) - off,
					"%02x ", first_bytes[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < 8; i++)
			off += snprintf(recheck_hex + off, sizeof(recheck_hex) - off,
					"%02x ", recheck_bytes[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:file_getattr] dfd=%d path=%s usize=%zu [%s] vs [%s]\n",
		       dfd, path_local, usize, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.file_getattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_file_getattr = {
	.name = "file_getattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "ufattr", [3] = "usize", [4] = "at_flags" },
	.arg_params[4].list = ARGLIST(file_getattr_at_flags),
	.sanitise = sanitise_file_getattr,
	.post = post_file_getattr,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
