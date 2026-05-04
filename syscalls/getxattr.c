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
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "xattr.h"

#if defined(SYS_getxattr) || defined(__NR_getxattr)
/*
 * Snapshot of the three getxattr input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign value buffer or hand
 * the re-call the wrong (pathname, name) tuple.
 */
struct getxattr_post_state {
	unsigned long pathname;
	unsigned long name;
	unsigned long value;
};
#endif

static void sanitise_getxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);
#if defined(SYS_getxattr) || defined(__NR_getxattr)
	struct getxattr_post_state *snap;

	rec->post_state = 0;
#endif

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
	avoid_shared_buffer(&rec->a3, rec->a4);

#if defined(SYS_getxattr) || defined(__NR_getxattr)
	/*
	 * Snapshot the three input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated on
	 * SYS_getxattr to mirror the .post registration -- on systems
	 * without SYS_getxattr the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->pathname = rec->a1;
	snap->name     = rec->a2;
	snap->value    = rec->a3;
	rec->post_state = (unsigned long) snap;
#endif
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
 * TOCTOU defeat: the three input args (pathname, name, value) are
 * snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot redirect us at a foreign value buffer or hand the
 * re-call the wrong (pathname, name) tuple.  We still snapshot the
 * path, the name, and the first retval bytes of the receive buffer
 * into stack-locals before re-issuing, with a fresh private stack
 * buffer for the re-call (NOT the snapshot's value -- a sibling could
 * mutate the user buffer itself mid-syscall and forge a clean
 * compare).  Drop the sample if the re-call returns <= 0 (xattr was
 * removed between calls -- benign, ENOATTR/ENOENT/EACCES) or if it
 * returns a different length (sibling setxattr changed the value --
 * benign size-class drift).  Compare exactly snap_len bytes with
 * memcmp; do not early-return on first divergence so a multi-byte tear
 * surfaces in a single sample, but bump the anomaly counter only once.
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.
 *
 * On most fleets getxattr rarely succeeds (most paths have no xattrs)
 * and the retval > 0 gate keeps this oracle dormant; it costs ~zero
 * on no-xattr hosts and protects niche xattr-heavy ones.
 */
static void post_getxattr(struct syscallrecord *rec)
{
	struct getxattr_post_state *snap =
		(struct getxattr_post_state *) rec->post_state;
	char snap_path[PATH_MAX];
	char snap_name[256];
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
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getxattr: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval <= 0)
		goto out_free;

	if (snap->value == 0 || snap->pathname == 0 || snap->name == 0)
		goto out_free;

	{
		void *value = (void *)(unsigned long) snap->value;
		void *path = (void *)(unsigned long) snap->pathname;
		void *name = (void *)(unsigned long) snap->name;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled value/pathname/name before
		 * deref.
		 */
		if (looks_like_corrupted_ptr(rec, value) ||
		    looks_like_corrupted_ptr(rec, path) ||
		    looks_like_corrupted_ptr(rec, name)) {
			outputerr("post_getxattr: rejected suspicious value=%p path=%p name=%p (post_state-scribbled?)\n",
				  value, path, name);
			goto out_free;
		}
	}

	strncpy(snap_path, (char *)(unsigned long) snap->pathname, sizeof(snap_path) - 1);
	snap_path[sizeof(snap_path) - 1] = '\0';

	strncpy(snap_name, (char *)(unsigned long) snap->name, sizeof(snap_name) - 1);
	snap_name[sizeof(snap_name) - 1] = '\0';

	snap_len = (size_t) rec->retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);

	memcpy(first_buf, (void *)(unsigned long) snap->value, snap_len);

	rc = syscall(SYS_getxattr, snap_path, snap_name,
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
		       "[oracle:getxattr] path=%s name=%s len=%zu first %s vs recheck %s\n",
		       snap_path, snap_name, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.getxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
