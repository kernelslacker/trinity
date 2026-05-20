/*
 * SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
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

#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
/*
 * Snapshot of the three lgetxattr input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign value buffer or hand
 * the re-call the wrong (pathname, name) tuple.
 */
#define LGETXATTR_POST_STATE_MAGIC	0x4C475852UL	/* "LGXR" */
struct lgetxattr_post_state {
	unsigned long magic;
	unsigned long pathname;
	unsigned long name;
	unsigned long value;
	size_t buf_alloc_size;
};
#endif

static void sanitise_lgetxattr(struct syscallrecord *rec)
{
#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	struct lgetxattr_post_state *snap;
	unsigned long pre_a3;
	size_t buf_alloc_size;

	rec->post_state = 0;
#endif

	if (!sanitise_xattr_name_arg(rec, 2))
		return;
#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	pre_a3 = rec->a3;
#endif
	avoid_shared_buffer_out(&rec->a3, rec->a4);

#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	/*
	 * Resolve the actual allocation size of the buffer at rec->a3 and
	 * clamp rec->a4 (size) to it before the kernel sees the syscall.
	 * rec->a4 comes from ARG_LEN / get_len() which freely returns
	 * UINT_MAX-class values picked independently of the pool slot at
	 * rec->a3.  The kernel's vfs_getxattr writes min(size, value_len)
	 * bytes into the user buffer; when size > the live allocation the
	 * write spills into adjacent heap-arena / pool-neighbour objects
	 * and corrupts glibc chunk metadata, with the abort surfacing far
	 * downstream (deferred_free_flush, _int_malloc on a corrupted
	 * tcache, etc.).  Same shape as the sched_getattr clamp
	 * (862ee5c6ae3a), applied here to the pool-backed ARG_ADDRESS
	 * buffer family.
	 *
	 *   - If avoid_shared_buffer_out() redirected (pointer changed),
	 *     the replacement came from get_writable_address(rec->a4) and
	 *     is at least max(rec->a4, page_size) bytes.
	 *   - Otherwise rec->a3 is the original ARG_ADDRESS pool slot from
	 *     get_address() -> get_writable_address(RAND_ARRAY(
	 *     mapping_sizes)); mapping_sizes[0] == page_size so the slot
	 *     is provably at least page_size bytes, the conservative bound
	 *     we can prove without re-resolving the slot.
	 */
	if (rec->a3 != pre_a3)
		buf_alloc_size = rec->a4 > (unsigned long) page_size
				       ? (size_t) rec->a4
				       : (size_t) page_size;
	else
		buf_alloc_size = (size_t) page_size;

	if ((size_t) rec->a4 > buf_alloc_size)
		rec->a4 = (unsigned long) buf_alloc_size;

	/*
	 * Snapshot the three input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original user
	 * buffer pointers, so the memcpy / re-call would touch a foreign
	 * allocation.  post_state is private to the post handler.  Gated on
	 * SYS_lgetxattr to mirror the .post registration -- on systems
	 * without SYS_lgetxattr the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = LGETXATTR_POST_STATE_MAGIC;
	snap->pathname = rec->a1;
	snap->name     = rec->a2;
	snap->value    = rec->a3;
	snap->buf_alloc_size = buf_alloc_size;
	rec->post_state = (unsigned long) snap;
#endif
}

#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
#ifndef SYS_lgetxattr
#define SYS_lgetxattr __NR_lgetxattr
#endif

/*
 * Oracle: lgetxattr(path, name, value, size) reads the named extended
 * attribute of `path` into the user buffer at `value`, returning the
 * number of bytes written.  Unlike getxattr(), lgetxattr does not
 * follow symlinks -- it operates on the link itself.  Two back-to-back
 * lookups of the same (path, name) pair from the same task -- assuming
 * no sibling lsetxattr/lremovexattr races in between -- must produce
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
 * returns a different length (sibling lsetxattr changed the value --
 * benign size-class drift).  Compare exactly snap_len bytes with
 * memcmp; do not early-return on first divergence so a multi-byte tear
 * surfaces in a single sample, but bump the anomaly counter only once.
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.
 *
 * On most fleets lgetxattr rarely succeeds (most paths have no xattrs)
 * and the retval > 0 gate keeps this oracle dormant; it costs ~zero
 * on no-xattr hosts and protects niche xattr-heavy ones.
 */
static void post_lgetxattr(struct syscallrecord *rec)
{
	struct lgetxattr_post_state *snap =
		(struct lgetxattr_post_state *) rec->post_state;
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
		outputerr("post_lgetxattr: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * lgetxattr_post_state.  A cookie mismatch means snap does not
	 * point at our struct -- abandon rather than feed wild bytes into
	 * the pathname / name / value inner derefs and re-issue recheck.
	 */
	if (snap->magic != LGETXATTR_POST_STATE_MAGIC) {
		outputerr("post_lgetxattr: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	/*
	 * STRONG-VAL count bound: lgetxattr(2) on success returns the number
	 * of bytes the VFS copied into the user `value` buffer, capped at the
	 * `size` argument (rec->a4) by vfs_getxattr's truncation; failure
	 * returns -1UL.  A retval > size on a non-(-1UL) return is structurally
	 * impossible from the VFS path -- it points at a sign-extension tear,
	 * a sibling-stomp of rec->retval between syscall return and post entry,
	 * or -errno leaking through the success slot.  Fire unconditionally,
	 * ahead of the ONE_IN(100) sample gate that throttles the equality
	 * oracle, so every offending retval is counted, not one-in-a-hundred.
	 * The pre-existing retval <= 0 gate after the sample stays in place.
	 */
	if ((long) rec->retval < 0)
		goto out_free;
	if (rec->retval > rec->a4) {
		outputerr("post_lgetxattr: rejecting retval %lu > size %lu\n",
			  rec->retval, rec->a4);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
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
			outputerr("post_lgetxattr: rejected suspicious value=%p path=%p name=%p (post_state-scribbled?)\n",
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
	/*
	 * Belt-and-braces: the sanitise-time clamp guarantees the kernel
	 * could not have written past snap->buf_alloc_size, so the retval
	 * never legitimately exceeds it.  Cap snap_len explicitly so a
	 * sibling-stomped rec->retval cannot turn the memcpy below into a
	 * read-OOB on the pool slot backing snap->value.
	 */
	if (snap->buf_alloc_size != 0 && snap_len > snap->buf_alloc_size)
		snap_len = snap->buf_alloc_size;

	memcpy(first_buf, (void *)(unsigned long) snap->value, snap_len);

	rc = syscall(SYS_lgetxattr, snap_path, snap_name,
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
		       "[oracle:lgetxattr] path=%s name=%s len=%zu first %s vs recheck %s\n",
		       snap_path, snap_name, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.lgetxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif /* SYS_lgetxattr || __NR_lgetxattr */

struct syscallentry syscall_lgetxattr = {
	.name = "lgetxattr",
	.num_args = 4,
	.argtype = { [0] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_lgetxattr,
#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	.post = post_lgetxattr,
#endif
};
