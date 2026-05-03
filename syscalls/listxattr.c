#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_listxattr(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, rec->a3);
}

/*
 * SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
 */
#if defined(SYS_flistxattr) || defined(__NR_flistxattr)
#ifndef SYS_flistxattr
#define SYS_flistxattr __NR_flistxattr
#endif

/*
 * Oracle: flistxattr(fd, list, size) fills `list` with the NUL-separated
 * names of the extended attributes attached to the open file referred to
 * by `fd`, returning the byte length of the namebuffer it wrote.  This
 * is the fd-based variant of listxattr/llistxattr -- the lookup target
 * is the inode pinned by the open file description, not a path walk, so
 * it sidesteps dcache/mount-namespace effects entirely.  Two back-to-back
 * lookups of the same fd from the same task -- assuming no sibling
 * fsetxattr/fremovexattr races in between -- must produce a byte-identical
 * name list of identical length.  A divergence between the original
 * syscall payload and an immediate re-call points at one of:
 *
 *   - copy_to_user mis-write into the wrong user slot, leaving the
 *     original receive buffer torn (partial write, wrong-offset fill,
 *     residual stack data) while the re-call lands clean.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - 32-on-64 compat ABI truncating a size_t and shipping a short
 *     payload while reporting the full retval.
 *   - fd table refcount underflow or dup race handing the second
 *     lookup a different file (or a recycled struct file) for the same
 *     fd number, where the xattr name set differs between the two inodes.
 *
 * TOCTOU defeat: the fd (rec->a1) and list buffer (rec->a2) are both
 * reachable from sibling trinity children and a concurrent write can
 * scribble either between the original return and our re-issue.
 * Snapshot the fd and the first retval bytes of the receive buffer to
 * stack-locals BEFORE re-issuing the syscall.  The re-call MUST target
 * a fresh stack buffer, never rec->a2 -- a sibling could mutate the
 * original receive buffer mid-syscall and forge a clean compare.  Drop
 * the sample if the re-call returns <= 0 (fd was closed by a sibling
 * close-racer -- benign EBADF; or all xattrs removed -- benign 0) or
 * if it returns a different length (sibling fsetxattr/fremovexattr
 * changed the name set -- benign size-class drift).  Compare exactly
 * snap_len bytes with memcmp; do not early-return on first divergence
 * so a multi-byte tear surfaces in a single sample, but bump the
 * anomaly counter only once.  Sample one in a hundred to stay in line
 * with the rest of the oracle family.
 *
 * fd 0 is stdin -- a perfectly valid fd to query xattrs on -- so do
 * not gate it out the way path-based variants gate empty paths;
 * instead drop only on negative snapshotted fds.
 *
 * On most fleets flistxattr rarely returns a non-empty list (most
 * files have no xattrs) and the retval > 0 gate keeps this oracle
 * dormant; it costs ~zero on no-xattr hosts and protects niche
 * xattr-heavy ones.
 */
static void post_flistxattr(struct syscallrecord *rec)
{
	int snap_fd = (int) rec->a1;
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	if (rec->a2 == 0)
		return;

	if (snap_fd < 0)
		return;

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) rec->a2, snap_len);

	rc = syscall(SYS_flistxattr, snap_fd, recheck_buf, sizeof(recheck_buf));

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
		       "[oracle:flistxattr] fd=%d len=%zu first %s vs recheck %s\n",
		       snap_fd, snap_len, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.flistxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}
#endif /* SYS_flistxattr || __NR_flistxattr */

struct syscallentry syscall_flistxattr = {
	.name = "flistxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "list", [2] = "size" },
	.sanitise = sanitise_listxattr,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
#if defined(SYS_flistxattr) || defined(__NR_flistxattr)
	.post = post_flistxattr,
#endif
};

/*
 * SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list, size_t, size
 */
struct syscallentry syscall_listxattr = {
	.name = "listxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "list", [2] = "size" },
	.sanitise = sanitise_listxattr,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list, size_t, size)
 */
struct syscallentry syscall_llistxattr = {
	.name = "llistxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "list", [2] = "size" },
	.sanitise = sanitise_listxattr,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
