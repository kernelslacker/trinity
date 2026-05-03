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
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long listxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

static void sanitise_listxattrat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a4, rec->a5);
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
 * TOCTOU defeat: the dfd (rec->a1), pathname (rec->a2), at_flags
 * (rec->a3), and list buffer (rec->a4) are all reachable from sibling
 * trinity children and a concurrent write can scribble any of them
 * between the original return and our re-issue.  Snapshot the dfd, the
 * pathname, the at_flags, and the first retval bytes of the receive
 * buffer to stack-locals BEFORE re-issuing the syscall.  The re-call
 * MUST target a fresh stack buffer, never rec->a4 -- a sibling could
 * mutate the original receive buffer mid-syscall and forge a clean
 * compare.  Drop the sample if the re-call returns <= 0 (xattrs were
 * removed between calls -- benign, returns 0 or ENOENT) or if it
 * returns a different length (sibling [l|f]setxattr/[l|f]removexattr
 * changed the name set -- benign size-class drift).  Compare exactly
 * snap_len bytes with memcmp; do not early-return on first divergence
 * so a multi-byte tear surfaces in a single sample, but bump the
 * anomaly counter only once.  Sample one in a hundred to stay in line
 * with the rest of the oracle family.
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
	int snap_dfd = (int) rec->a1;
	char snap_path[PATH_MAX];
	unsigned int snap_at_flags = (unsigned int) rec->a3;
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	if (rec->a4 == 0)
		return;

	if (rec->a2 == 0)
		return;

	{
		void *list_p = (void *)(unsigned long) rec->a4;
		void *path_p = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a4/a2. */
		if (looks_like_corrupted_ptr(list_p) ||
		    looks_like_corrupted_ptr(path_p)) {
			outputerr("post_listxattrat: rejected suspicious list=%p pathname=%p (pid-scribbled?)\n",
				  list_p, path_p);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	strncpy(snap_path, (char *)(unsigned long) rec->a2, sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) rec->a4, snap_len);

	rc = syscall(SYS_listxattrat, snap_dfd, snap_path, snap_at_flags,
		     recheck_buf, sizeof(recheck_buf));

	if (rc <= 0)
		return;

	if ((size_t) rc != snap_len)
		return;

	if (memcmp(first_buf, recheck_buf, snap_len) == 0)
		return;

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
