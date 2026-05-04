/*
 * SYSCALL_DEFINE5(listxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, char __user *, list, size_t, size)
 */
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/limits.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long listxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
/*
 * Snapshot of the four listxattrat input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign list buffer or hand
 * the re-call the wrong (dfd, pathname, at_flags) tuple.
 */
struct listxattrat_post_state {
	unsigned long dfd;
	unsigned long pathname;
	unsigned long at_flags;
	unsigned long list;
};
#endif

static void sanitise_listxattrat(struct syscallrecord *rec)
{
#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
	struct listxattrat_post_state *snap;

	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a4, rec->a5);

#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
	/*
	 * Snapshot all four input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated
	 * on SYS_listxattrat to mirror the .post registration -- on systems
	 * without SYS_listxattrat the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->dfd      = rec->a1;
	snap->pathname = rec->a2;
	snap->at_flags = rec->a3;
	snap->list     = rec->a4;
	rec->post_state = (unsigned long) snap;
#endif
}

#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
#ifndef SYS_listxattrat
#define SYS_listxattrat __NR_listxattrat
#endif

/*
 * Oracle: listxattrat(dfd, pathname, at_flags, list, size) fills `list`
 * with the NUL-separated names of the extended attributes attached to
 * the inode resolved at (dfd, pathname), returning the byte length of
 * the namebuffer it wrote.  Two back-to-back lookups of the same
 * (dfd, pathname, at_flags) tuple from the same task -- assuming no
 * sibling [l|f]setxattr/[l|f]removexattr races in between -- must
 * produce a byte-identical name list of identical length.  A divergence
 * between the original syscall payload and an immediate re-call points
 * at one of:
 *
 *   - copy_to_user mis-write into the wrong user slot, leaving the
 *     original receive buffer torn (partial write, wrong-offset fill,
 *     residual stack data) while the re-call lands clean.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - 32-on-64 compat ABI truncating a size_t and shipping a short
 *     payload while reporting the full retval.
 *   - dentry/inode cache reuse or refcount underflow handing the second
 *     lookup a different inode for the same (dfd, pathname), where the
 *     xattr name set differs between the two inodes.
 *
 * TOCTOU defeat: the four input args (dfd, pathname, at_flags, list)
 * are snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot redirect us at a foreign list buffer or hand the re-call
 * the wrong (dfd, pathname, at_flags) tuple.  We still snapshot the
 * pathname bytes and the first retval bytes of the receive buffer into
 * stack-locals before re-issuing, with a fresh private stack buffer for
 * the re-call (NOT the snapshot's list -- a sibling could mutate the
 * user buffer itself mid-syscall and forge a clean compare).  Drop the
 * sample if the re-call returns <= 0 (xattrs were removed between calls
 * -- benign, returns 0 or ENOENT) or if it returns a different length
 * (sibling [l|f]setxattr/[l|f]removexattr changed the name set --
 * benign size-class drift).  Compare exactly snap_len bytes with
 * memcmp; do not early-return on first divergence so a multi-byte tear
 * surfaces in a single sample, but bump the anomaly counter only once.
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.
 *
 * AT_FDCWD is a perfectly valid (negative) dfd value, so do not gate
 * on negative snapshotted dfds the way fd-only oracles do.
 *
 * On most fleets listxattrat rarely returns a non-empty list (most
 * paths have no xattrs) and the retval > 0 gate keeps this oracle
 * dormant; it costs ~zero on no-xattr hosts and protects niche
 * xattr-heavy ones.
 */
static void post_listxattrat(struct syscallrecord *rec)
{
	struct listxattrat_post_state *snap =
		(struct listxattrat_post_state *) rec->post_state;
	int snap_dfd;
	char snap_path[PATH_MAX];
	unsigned int snap_at_flags;
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_listxattrat: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval <= 0)
		goto out_free;

	if (snap->list == 0)
		goto out_free;

	if (snap->pathname == 0)
		goto out_free;

	{
		void *list_p = (void *)(unsigned long) snap->list;
		void *path_p = (void *)(unsigned long) snap->pathname;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled list/pathname before deref.
		 */
		if (looks_like_corrupted_ptr(list_p) ||
		    looks_like_corrupted_ptr(path_p)) {
			outputerr("post_listxattrat: rejected suspicious list=%p pathname=%p (post_state-scribbled?)\n",
				  list_p, path_p);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	snap_dfd = (int) snap->dfd;
	snap_at_flags = (unsigned int) snap->at_flags;

	strncpy(snap_path, (char *)(unsigned long) snap->pathname,
		sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) snap->list, snap_len);

	rc = syscall(SYS_listxattrat, snap_dfd, snap_path, snap_at_flags,
		     recheck_buf, sizeof(recheck_buf));

	if (rc <= 0)
		goto out_free;

	if ((size_t) rc != snap_len)
		goto out_free;

	if (memcmp(first_buf, recheck_buf, snap_len) == 0)
		goto out_free;

	{
		char first_hex[32 * 2 + 1];
		char recheck_hex[32 * 2 + 1];
		size_t i, dump_len;

		dump_len = snap_len < 32 ? snap_len : 32;
		for (i = 0; i < dump_len; i++) {
			snprintf(first_hex + i * 2, 3, "%02x",
				 (unsigned char) first_buf[i]);
			snprintf(recheck_hex + i * 2, 3, "%02x",
				 (unsigned char) recheck_buf[i]);
		}
		first_hex[dump_len * 2] = '\0';
		recheck_hex[dump_len * 2] = '\0';

		output(0,
		       "[oracle:listxattrat] dfd=%d path=%s at_flags=0x%x len=%zu first %s vs recheck %s\n",
		       snap_dfd, snap_path, snap_at_flags, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.listxattrat_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif /* SYS_listxattrat || __NR_listxattrat */

struct syscallentry syscall_listxattrat = {
	.name = "listxattrat",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_ADDRESS, [4] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "list", [4] = "size" },
	.arg_params[2].list = ARGLIST(listxattrat_at_flags),
	.sanitise = sanitise_listxattrat,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
	.post = post_listxattrat,
#endif
};
