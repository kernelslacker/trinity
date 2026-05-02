/*
 * SYSCALL_DEFINE4(getxattr, const char __user *, pathname,
	 const char __user *, name, void __user *, value, size_t, size)
 */
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
#include "xattr.h"

static void sanitise_getxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
	avoid_shared_buffer(&rec->a3, rec->a4);
}

#if defined(SYS_getxattr) || defined(__NR_getxattr)
#ifndef SYS_getxattr
#define SYS_getxattr __NR_getxattr
#endif

/*
 * Oracle: getxattr(path, name, value, size) reads the named extended
 * attribute of `path` into the user buffer at `value`, returning the
 * number of bytes written.  Two back-to-back lookups of the same
 * (path, name) pair from the same task -- assuming no sibling
 * setxattr/removexattr races in between -- must produce a byte-identical
 * payload of identical length.  A divergence between the original
 * syscall payload and an immediate re-call points at one of:
 *
 *   - copy_to_user mis-write into the wrong user slot, leaving the
 *     original receive buffer torn (partial write, wrong-offset fill,
 *     residual stack data) while the re-call lands clean.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - 32-on-64 compat ABI truncating a size_t and shipping a short
 *     payload while reporting the full retval.
 *   - dentry/inode cache reuse or refcount underflow handing the second
 *     lookup a different inode for the same path, where the xattr value
 *     differs between the two inodes.
 *
 * TOCTOU defeat: the path (rec->a1), name (rec->a2), and value buffer
 * (rec->a3) are all reachable from sibling trinity children and a
 * concurrent write can scribble any of them between the original return
 * and our re-issue.  Snapshot the path, the name, and the first retval
 * bytes of the receive buffer to stack-locals BEFORE re-issuing the
 * syscall.  The re-call MUST target a fresh stack buffer, never
 * rec->a3 -- a sibling could mutate the original receive buffer
 * mid-syscall and forge a clean compare.  Drop the sample if the
 * re-call returns <= 0 (xattr was removed between calls -- benign,
 * ENOATTR/ENOENT/EACCES) or if it returns a different length (sibling
 * setxattr changed the value -- benign size-class drift).  Compare
 * exactly snap_len bytes with memcmp; do not early-return on first
 * divergence so a multi-byte tear surfaces in a single sample, but
 * bump the anomaly counter only once.  Sample one in a hundred to
 * stay in line with the rest of the oracle family.
 *
 * On most fleets getxattr rarely succeeds (most paths have no xattrs)
 * and the retval > 0 gate keeps this oracle dormant; it costs ~zero
 * on no-xattr hosts and protects niche xattr-heavy ones.
 */
static void post_getxattr(struct syscallrecord *rec)
{
	char snap_path[PATH_MAX];
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

	if (rec->a1 == 0)
		return;

	if (rec->a2 == 0)
		return;

	strncpy(snap_path, (char *)(unsigned long) rec->a1, sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	strncpy(snap_name, (char *)(unsigned long) rec->a2, sizeof(snap_name) - 1);
	snap_name[sizeof(snap_name) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) rec->a3, snap_len);

	rc = syscall(SYS_getxattr, snap_path, snap_name,
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
		       "[oracle:getxattr] path=%s name=%s len=%zu first %s vs recheck %s\n",
		       snap_path, snap_name, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.getxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}
#endif /* SYS_getxattr || __NR_getxattr */

struct syscallentry syscall_getxattr = {
	.name = "getxattr",
	.num_args = 4,
	.argtype = { [0] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_getxattr,
#if defined(SYS_getxattr) || defined(__NR_getxattr)
	.post = post_getxattr,
#endif
};
