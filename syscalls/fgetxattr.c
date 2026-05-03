/*
 * SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
	 void __user *, value, size_t, size)
 */
#include <stddef.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "xattr.h"

static void sanitise_fgetxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
	avoid_shared_buffer(&rec->a3, rec->a4);
}

#if defined(SYS_fgetxattr) || defined(__NR_fgetxattr)
#ifndef SYS_fgetxattr
#define SYS_fgetxattr __NR_fgetxattr
#endif

/*
 * Oracle: fgetxattr(fd, name, value, size) reads the named extended
 * attribute of the open file referred to by `fd` into the user buffer
 * at `value`, returning the number of bytes written.  This is the
 * fd-based variant of getxattr/lgetxattr -- the lookup target is the
 * inode pinned by the open file description, not a path walk, so it
 * sidesteps dcache/mount-namespace effects entirely.  Two back-to-back
 * lookups of the same (fd, name) pair from the same task -- assuming
 * no sibling fsetxattr/fremovexattr races in between -- must produce
 * a byte-identical payload of identical length.  A divergence between
 * the original syscall payload and an immediate re-call points at one
 * of:
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
 *     fd number, where the xattr value differs between the two inodes.
 *
 * TOCTOU defeat: the fd (rec->a1), name (rec->a2), and value buffer
 * (rec->a3) are all reachable from sibling trinity children and a
 * concurrent write can scribble any of them between the original return
 * and our re-issue.  Snapshot the fd, the name, and the first retval
 * bytes of the receive buffer to stack-locals BEFORE re-issuing the
 * syscall.  The re-call MUST target a fresh stack buffer, never
 * rec->a3 -- a sibling could mutate the original receive buffer
 * mid-syscall and forge a clean compare.  Drop the sample if the
 * re-call returns <= 0 (fd was closed by a sibling close-racer --
 * benign EBADF; or xattr removed -- benign ENOATTR) or if it returns
 * a different length (sibling fsetxattr changed the value -- benign
 * size-class drift).  Compare exactly snap_len bytes with memcmp; do
 * not early-return on first divergence so a multi-byte tear surfaces
 * in a single sample, but bump the anomaly counter only once.  Sample
 * one in a hundred to stay in line with the rest of the oracle family.
 *
 * fd 0 is stdin -- a perfectly valid fd to query xattrs on -- so do
 * not gate it out the way path-based variants gate empty paths;
 * instead drop only on negative snapshotted fds.
 *
 * On most fleets fgetxattr rarely succeeds (most files have no xattrs)
 * and the retval > 0 gate keeps this oracle dormant; it costs ~zero
 * on no-xattr hosts and protects niche xattr-heavy ones.
 */
static void post_fgetxattr(struct syscallrecord *rec)
{
	int snap_fd = (int) rec->a1;
	char snap_name[256];
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval <= 0)
		return;

	if (rec->a3 == 0)
		return;

	if (snap_fd < 0)
		return;

	if (rec->a2 == 0)
		return;

	{
		void *value = (void *)(unsigned long) rec->a3;
		void *name = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a3/a2. */
		if (looks_like_corrupted_ptr(value) || looks_like_corrupted_ptr(name)) {
			outputerr("post_fgetxattr: rejected suspicious value=%p name=%p (pid-scribbled?)\n",
				  value, name);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	strncpy(snap_name, (char *)(unsigned long) rec->a2, sizeof(snap_name) - 1);
	snap_name[sizeof(snap_name) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) rec->a3, snap_len);

	rc = syscall(SYS_fgetxattr, snap_fd, snap_name,
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
		       "[oracle:fgetxattr] fd=%d name=%s len=%zu first %s vs recheck %s\n",
		       snap_fd, snap_name, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.fgetxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}
#endif /* SYS_fgetxattr || __NR_fgetxattr */

struct syscallentry syscall_fgetxattr = {
	.name = "fgetxattr",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "name", [2] = "value", [3] = "size" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fgetxattr,
#if defined(SYS_fgetxattr) || defined(__NR_fgetxattr)
	.post = post_fgetxattr,
#endif
};
