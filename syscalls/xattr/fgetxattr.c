/*
 * SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
	 void __user *, value, size_t, size)
 */
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <string.h>
#include "arch.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "testfile.h"
#include "trinity.h"
#include "utils.h"
#include "xattr.h"

/*
 * Curated name we plant ahead of the trinity-dispatched fgetxattr.
 * user.* requires no privilege, is supported on every Linux fs that
 * carries xattrs at all, and lives in the curated pool the
 * ARG_XATTR_NAME draw already favours -- so the plant overlaps with
 * the existing name distribution instead of introducing a fresh
 * namespace the kernel rejects up front.
 */
static const char planted_xattr_name[] = "user.trinity_plant";

#if defined(SYS_fgetxattr) || defined(__NR_fgetxattr)
/*
 * Snapshot of the fgetxattr input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign value buffer or hand
 * the re-call the wrong fd.  The xattr name is snapshotted by VALUE into
 * the embedded byte buffer below rather than by pointer -- a stale
 * heap-shaped name pointer that survived looks_like_corrupted_ptr's
 * shape-only gate would otherwise let the .post strncpy walk off the
 * end of an unrelated allocation, and a sibling rewrite of the bytes
 * between sanitise and post would hand the re-call the wrong name and
 * forge a clean-looking divergence.
 */
#define FGETXATTR_POST_STATE_MAGIC	0x46475852UL	/* "FGXR" */
struct fgetxattr_post_state {
	unsigned long magic;
	unsigned long fd;
	unsigned long value;
	unsigned long size;
	size_t buf_alloc_size;
	char name[256];
};
#endif

#if defined(SYS_fgetxattr) || defined(__NR_fgetxattr)
static void sanitise_fgetxattr_install_post_snapshot(struct syscallrecord *rec,
						     unsigned long pre_a3)
{
	struct fgetxattr_post_state *snap;
	size_t buf_alloc_size;

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
	 * Snapshot input state for the post oracle.  Without this the
	 * post handler reads rec->aN at post-time, when a sibling syscall
	 * may have scribbled the slots: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original user value
	 * pointer, so the memcpy would touch a foreign allocation, and a
	 * stale rec->a2 / sibling-rewritten name bytes would hand the
	 * re-call the wrong xattr name.  Snapshot the name BYTES via
	 * post_snapshot_str so the post handler never re-derefs the user
	 * pointer; skip the post sample when the snapshot source is not
	 * provably readable.  post_state is private to the post handler.
	 * Gated on SYS_fgetxattr to mirror the .post registration -- on
	 * systems without SYS_fgetxattr the post handler is not registered
	 * and a snapshot only the post handler can free would leak.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_fgetxattr() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = FGETXATTR_POST_STATE_MAGIC;
	snap->fd    = rec->a1;
	snap->value = rec->a3;
	snap->size  = rec->a4;
	snap->buf_alloc_size = buf_alloc_size;
	if (!post_snapshot_str(snap->name, sizeof(snap->name),
			       (const char *)(unsigned long) rec->a2))
		snap->name[0] = '\0';
	post_state_install(rec, snap);
}
#endif

static void sanitise_fgetxattr(struct syscallrecord *rec)
{
#if defined(SYS_fgetxattr) || defined(__NR_fgetxattr)
	unsigned long pre_a3;

	rec->post_state = 0;
	pre_a3 = rec->a3;
#endif

	/*
	 * ARG_FD plumbed a random fd into rec->a1 and ARG_XATTR_NAME
	 * filled rec->a2 with a namespace-shaped name from the curated
	 * pool.  But the fd is most often the wrong kind of object for
	 * an xattr op (socket, pipe, eventfd, mq, ...) or, even when it
	 * lands on a real file, the drawn name is not currently set --
	 * vfs_getxattr returns ENOTSUP / ENODATA at the front of the
	 * call before ever touching the per-fs handler dispatch or the
	 * simple_xattr_get fast path that the per-inode i_xattrs rwsem
	 * guards.  "high calls, low edges" cold-syscall shape that the
	 * wall-lever shadow gate keeps re-flagging.
	 *
	 * Half the draws now repoint at a testfile fd and plant a known
	 * user.* xattr there via fsetxattr() so the subsequent fgetxattr
	 * lands inside the real per-inode lookup path.  The other half
	 * preserves the slot exactly as the generic draw left it, so the
	 * namespace-reject / ENODATA arms stay exercised.
	 *
	 * Plant runs BEFORE the post_state snapshot below so the oracle
	 * re-walks the planted (fd, name) tuple, not the pre-plant one.
	 *
	 * Slow-path note: fsetxattr() inside sanitise is a real syscall.
	 * syscalls/fgetxattr.c is outside the sanitiser-slow-path check's
	 * FILES scope, so this is within budget for the precondition
	 * payoff (zero per-inode-get edges -> real get edges).
	 */
	if (rnd_modulo_u32(2) == 0) {
		int fd = get_rand_testfile_fd();

		if (fd >= 0) {
			char *name = (char *) rec->a2;

			if (name != NULL) {
				/* Overwrite the ARG_XATTR_NAME-allocated
				 * buffer in place so the plant we make from
				 * sanitise and the trinity-dispatched
				 * fgetxattr that follows see the same byte
				 * sequence.  Buffer is XATTR_NAME_BUFSZ
				 * (256); planted_xattr_name fits with room
				 * to spare. */
				memcpy(name, planted_xattr_name,
				       sizeof(planted_xattr_name));

				/* Plant a small opaque value.  Failure here
				 * (ENOSPC on full xattr list, EOPNOTSUPP on
				 * an fs that bailed out of the user.* leg,
				 * ...) is non-fatal: an earlier draw on the
				 * same fd may still hold a stale
				 * user.trinity_plant from a prior round, so
				 * fgetxattr below may still land on the real
				 * get path. */
				(void) fsetxattr(fd, name, "trin", 4, 0);

				rec->a1 = (unsigned long) fd;
			}
		}
	}

	xattr_pick_valuebuf_bucket(&rec->a3, &rec->a4);
	avoid_shared_buffer_out(&rec->a3, rec->a4);

#if defined(SYS_fgetxattr) || defined(__NR_fgetxattr)
	sanitise_fgetxattr_install_post_snapshot(rec, pre_a3);
#endif
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
 * TOCTOU defeat: the three input args (fd, name, value) are
 * snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot redirect us at a foreign value buffer or hand the
 * re-call the wrong (fd, name) tuple.  We still snapshot the name and
 * the first retval bytes of the receive buffer into stack-locals
 * before re-issuing, with a fresh private stack buffer for the re-call
 * (NOT the snapshot's value -- a sibling could mutate the user buffer
 * itself mid-syscall and forge a clean compare).  Drop the sample if
 * the re-call returns <= 0 (fd was closed by a sibling close-racer --
 * benign EBADF; or xattr removed -- benign ENOATTR) or if it returns a
 * different length (sibling fsetxattr changed the value -- benign
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
	struct fgetxattr_post_state *snap;
	unsigned long retval = rec->retval;
	int snap_fd;
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, FGETXATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * STRONG-VAL count bound: fgetxattr(2) on success returns the number
	 * of bytes written into the user `value` buffer, which the kernel caps
	 * at the `size` argument (rec->a4) via vfs_getxattr's truncation;
	 * failure returns -1UL.  A retval > size on a non-(-1UL) return is
	 * structurally impossible from the VFS path -- it points at a
	 * sign-extension tear, a sibling-stomp of rec->retval between syscall
	 * return and post entry, or -errno leaking through the success slot.
	 * Fire unconditionally, ahead of the ONE_IN(100) sample gate that
	 * throttles the equality oracle, so every offending retval is counted,
	 * not one-in-a-hundred.
	 */
	if ((long) retval < 0)
		goto out_release;
	if (snap->size != 0 && retval > snap->size) {
		outputerr("post_fgetxattr: rejecting retval %lu > size %lu\n",
			  retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_release;
	}

	if (!ONE_IN(100))
		goto out_release;

	if ((long) retval <= 0)
		goto out_release;

	/* size=0 / NULL-buffer probe -- see post_getxattr for rationale. */
	if (snap->size == 0)
		goto out_release;

	if (snap->value == 0)
		goto out_release;

	if (snap->name[0] == '\0')
		goto out_release;

	snap_fd = (int) snap->fd;
	if (snap_fd < 0)
		goto out_release;

	snap_len = (size_t) retval;
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

	if (!post_snapshot_or_skip(first_buf,
				   (void *)(unsigned long) snap->value,
				   snap_len))
		goto out_release;

	rc = syscall(SYS_fgetxattr, snap_fd, snap->name,
		     recheck_buf, sizeof(recheck_buf));

	if (rc <= 0)
		goto out_release;

	if ((size_t) rc != snap_len)
		goto out_release;

	if (memcmp(first_buf, recheck_buf, snap_len) == 0)
		goto out_release;

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
		       snap_fd, snap->name, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.fgetxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
}
#endif /* SYS_fgetxattr || __NR_fgetxattr */

struct syscallentry syscall_fgetxattr = {
	.name = "fgetxattr",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_XATTR_NAME, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "name", [2] = "value", [3] = "size" },
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_fgetxattr,
#if defined(SYS_fgetxattr) || defined(__NR_fgetxattr)
	.post = post_fgetxattr,
#endif
};
