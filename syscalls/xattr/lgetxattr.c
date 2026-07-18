/*
 * SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
	 const char __user *, name, void __user *, value, size_t, size)
 */
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include "arch.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "xattr.h"

#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
/*
 * Snapshot of the lgetxattr input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign value buffer.  The
 * pathname and xattr name are snapshotted by VALUE into the embedded
 * byte buffers below rather than by pointer -- a stale heap-shaped
 * pointer that survived looks_like_corrupted_ptr's shape-only gate
 * would otherwise let the .post strncpy walk off the end of an
 * unrelated allocation, and a sibling rewrite of the bytes between
 * sanitise and post would hand the re-call the wrong (pathname, name)
 * tuple and forge a clean-looking divergence.
 */
#define LGETXATTR_POST_STATE_MAGIC	0x4C475852UL	/* "LGXR" */
struct lgetxattr_post_state {
	unsigned long magic;
	unsigned long value;
	unsigned long size;
	size_t buf_alloc_size;
	char pathname[PATH_MAX];
	char name[256];
};
#endif

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the fuzzer touches
 * (xattr-thrash, flock-thrash, fremovexattr, lremovexattr, llistxattr);
 * cross-process contention concentrates on the same per-inode i_xattrs
 * rwsem.
 */
#define LGETXATTR_NR_TESTFILES	4

/*
 * Curated name we plant ahead of the trinity-dispatched lgetxattr.
 * Matches planted_xattr_name in fremovexattr / lremovexattr /
 * llistxattr so a single round of testfile xattrs is shared across
 * the whole xattr-family precondition surface.
 */
static const char lgetxattr_planted_name[] = "user.trinity_plant";

/*
 * ARG_PATHNAME plumbed a random pathname into rec->a1 and
 * ARG_XATTR_NAME filled rec->a2 with a namespace-shaped name
 * from the curated pool, but the random path is most often not
 * a real file (ENOENT) or, even when it does land on a real
 * file, the drawn name is not currently set on that inode --
 * vfs_getxattr returns ENOTSUP / ENODATA at the front of the
 * call before ever touching the per-fs handler dispatch or the
 * simple_xattr_get fast path that the per-inode i_xattrs rwsem
 * guards.  Same "high calls, low edges" cold-syscall shape that
 * fremovexattr / lremovexattr / llistxattr were in before their
 * precondition fixes.
 *
 * Half the draws now repoint at one of the trinity-testfile<N>
 * absolute paths and plant a known user.* xattr there via
 * setxattr() so the subsequent lgetxattr lands inside the real
 * per-inode read path.  The plant runs BEFORE the post-state
 * snapshot below so snap->pathname and snap->name capture the
 * planted byte sequences -- the post oracle's re-call then
 * re-walks the planted (path, name) tuple and compares its
 * returned value against the first call's payload exactly as
 * the existing oracle expects, including the snap_len equality
 * gate that drops benign sibling-induced drift (e.g. a
 * concurrent lsetxattr that swapped the value out).
 *
 * The other half preserves rec->a1 / rec->a2 exactly as the
 * generic draw left them so the namespace-reject / ENODATA arms
 * stay exercised; the buffer-overwrite path is in-place so the
 * trinity dispatch, the plant, and the post-oracle re-call all
 * see the same byte sequence.  Plant failure (ENOSPC, EOPNOTSUPP
 * on a fs that bailed out of the user.* leg, ENOENT if the
 * testfile slot was never opened, ...) is non-fatal: an earlier
 * draw on the same inode may still hold a stale
 * user.trinity_plant from a prior round, so lgetxattr below may
 * still land on the real read path.
 *
 * Slow-path note: the setxattr() in sanitise is one real
 * syscall.  syscalls/lgetxattr.c is outside the
 * sanitiser-slow-path check's FILES scope, so this is within
 * budget for the precondition payoff.
 */
static void sanitise_lgetxattr_plant_pathname(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(2) == 0) {
		char *name = (char *) rec->a2;
		char *path;

		if (name != NULL) {
			/*
			 * The ARG_XATTR_NAME buffer at rec->a2 is
			 * XATTR_NAME_BUFSZ (256) bytes and is overwritten in
			 * place; it comfortably fits the planted value.
			 */
			path = get_testfile_path();
			if (path != NULL) {
				rec->a1 = (unsigned long) path;
				memcpy(name, lgetxattr_planted_name,
				       sizeof(lgetxattr_planted_name));
				(void) setxattr(path, name, "trin", 4, 0);
			}
		}
	}
}

#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
static void sanitise_lgetxattr_install_post_snapshot(struct syscallrecord *rec,
						     unsigned long pre_a3)
{
	struct lgetxattr_post_state *snap;
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
	 * stale rec->a1 / rec->a2 or sibling-rewritten pathname / name
	 * bytes would hand the re-call the wrong (pathname, name) tuple.
	 * Snapshot the pathname and name BYTES via post_snapshot_str so
	 * the post handler never re-derefs the user pointers; skip the
	 * post sample when either snapshot source is not provably
	 * readable.  post_state is private to the post handler.  Gated on
	 * SYS_lgetxattr to mirror the .post registration -- on systems
	 * without SYS_lgetxattr the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = LGETXATTR_POST_STATE_MAGIC;
	snap->value    = rec->a3;
	snap->size     = rec->a4;
	snap->buf_alloc_size = buf_alloc_size;
	if (!post_snapshot_str(snap->pathname, sizeof(snap->pathname),
			       (const char *)(unsigned long) rec->a1))
		snap->pathname[0] = '\0';
	if (!post_snapshot_str(snap->name, sizeof(snap->name),
			       (const char *)(unsigned long) rec->a2))
		snap->name[0] = '\0';
	post_state_install(rec, snap);
}
#endif

static void sanitise_lgetxattr(struct syscallrecord *rec)
{
#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	unsigned long pre_a3;

	rec->post_state = 0;
#endif

	sanitise_lgetxattr_plant_pathname(rec);

#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	pre_a3 = rec->a3;
#endif
	xattr_pick_valuebuf_bucket(&rec->a3, &rec->a4);
	avoid_shared_buffer_out(&rec->a3, rec->a4);

#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	sanitise_lgetxattr_install_post_snapshot(rec, pre_a3);
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
	struct lgetxattr_post_state *snap;
	unsigned long retval = rec->retval;
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
	snap = post_state_claim_owned(rec, LGETXATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

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
	if ((long) retval < 0)
		goto out_release;
	if (snap->size != 0 && retval > snap->size) {
		outputerr("post_lgetxattr: rejecting retval %lu > size %lu\n",
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

	if (snap->pathname[0] == '\0' || snap->name[0] == '\0')
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

	rc = syscall(SYS_lgetxattr, snap->pathname, snap->name,
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
		       "[oracle:lgetxattr] path=%s name=%s len=%zu first %s vs recheck %s\n",
		       snap->pathname, snap->name, snap_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.lgetxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
}
#endif /* SYS_lgetxattr || __NR_lgetxattr */

struct syscallentry syscall_lgetxattr = {
	.name = "lgetxattr",
	.num_args = 4,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_XATTR_NAME, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size" },
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_lgetxattr,
#if defined(SYS_lgetxattr) || defined(__NR_lgetxattr)
	.post = post_lgetxattr,
#endif
};
