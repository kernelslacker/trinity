#include <stddef.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
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
/*
 * Snapshot of the two listxattr-family input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign list buffer or hand
 * the re-call the wrong fd / pathname.  The arg1 field is interpreted as
 * an int fd by post_flistxattr and as a const char * pathname by
 * post_listxattr / post_llistxattr.
 *
 * The size field captures the advertised size after the sanitise-time
 * bucket-and-clamp pass; the post oracle uses it (rather than rec->aN
 * at post time) to gate out the size=0 probe case, where retval is the
 * required namebuffer size and the user buffer was not populated.
 */
#define LISTXATTR_POST_STATE_MAGIC	0x4C53545841545452UL	/* "LSTXATTR" */
struct listxattr_post_state {
	unsigned long magic;
	unsigned long arg1;
	unsigned long list;
	unsigned long size;
	size_t buf_alloc_size;
};

/*
 * SYSCALL_DEFINE3(flistxattr, int, fd, char __user *, list, size_t, size)
 */
#if defined(SYS_flistxattr) || defined(__NR_flistxattr)
#ifndef SYS_flistxattr
#define SYS_flistxattr __NR_flistxattr
#endif

static void sanitise_flistxattr(struct syscallrecord *rec)
{
	struct listxattr_post_state *snap;
	unsigned long pre_a2;
	size_t buf_alloc_size;

	rec->post_state = 0;

	pre_a2 = rec->a2;
	/*
	 * Buffer-size legality buckets: capture pre_a2 first so the
	 * existing pre/post comparison correctly sees a substituted
	 * buffer when the bucket helper plants one.
	 */
	xattr_pick_listbuf_bucket(&rec->a2, &rec->a3);
	avoid_shared_buffer_out(&rec->a2, rec->a3);

	/*
	 * Resolve the actual allocation size of the buffer at rec->a2 and
	 * clamp rec->a3 (size) to it before the kernel sees the syscall.
	 * rec->a3 comes from ARG_LEN / get_len() which freely returns
	 * UINT_MAX-class values picked independently of the pool slot at
	 * rec->a2.  The kernel's vfs_listxattr writes min(size, name_list_len)
	 * bytes into the user buffer; when size > the live allocation the
	 * write spills into adjacent heap-arena / pool-neighbour objects
	 * and corrupts glibc chunk metadata, with the abort surfacing far
	 * downstream (deferred_free_flush, _int_malloc on a corrupted
	 * tcache, etc.).  Same shape as the sched_getattr clamp
	 * (862ee5c6ae3a), applied here to the pool-backed ARG_ADDRESS
	 * buffer family.
	 *
	 *   - If avoid_shared_buffer_out() redirected (pointer changed),
	 *     the replacement came from get_writable_address(rec->a3) and
	 *     is at least max(rec->a3, page_size) bytes.
	 *   - Otherwise rec->a2 is the original ARG_ADDRESS pool slot from
	 *     get_address() -> get_writable_address(RAND_ARRAY(
	 *     mapping_sizes)); mapping_sizes[0] == page_size so the slot
	 *     is provably at least page_size bytes, the conservative bound
	 *     we can prove without re-resolving the slot.
	 */
	if (rec->a2 != pre_a2)
		buf_alloc_size = rec->a3 > (unsigned long) page_size
				       ? (size_t) rec->a3
				       : (size_t) page_size;
	else
		buf_alloc_size = (size_t) page_size;

	if ((size_t) rec->a3 > buf_alloc_size)
		rec->a3 = (unsigned long) buf_alloc_size;

	/*
	 * Snapshot the fd and list buffer pointer for the post oracle.
	 * Without this the post handler reads rec->a1/a2 at post-time, when
	 * a sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user buffer pointer, so the memcpy /
	 * re-call would touch a foreign allocation.  post_state is private
	 * to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = LISTXATTR_POST_STATE_MAGIC;
	snap->arg1 = rec->a1;
	snap->list = rec->a2;
	snap->size = rec->a3;
	snap->buf_alloc_size = buf_alloc_size;
	post_state_install(rec, snap);
}

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
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * a sibling that scribbles rec->aN between syscall return and post entry
 * cannot redirect us at a foreign list buffer or hand the re-call the
 * wrong fd.  We still snapshot the first retval bytes of the receive
 * buffer to a stack-local BEFORE re-issuing the syscall, with a fresh
 * private stack buffer for the re-call (NOT the snapshot's list -- a
 * sibling could mutate the user buffer itself mid-syscall and forge a
 * clean compare).  Drop the sample if the re-call returns <= 0 (fd was
 * closed by a sibling close-racer -- benign EBADF; or all xattrs
 * removed -- benign 0) or if it returns a different length (sibling
 * fsetxattr/fremovexattr changed the name set -- benign size-class
 * drift).  Compare exactly snap_len bytes with memcmp; do not
 * early-return on first divergence so a multi-byte tear surfaces in a
 * single sample, but bump the anomaly counter only once.  Sample one
 * in a hundred to stay in line with the rest of the oracle family.
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
	struct listxattr_post_state *snap;
	unsigned long retval = rec->retval;
	int snap_fd;
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	snap = post_state_claim_owned(rec, LISTXATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) retval < 0)
		goto out_free;
	if (snap->size != 0 && retval > snap->size) {
		outputerr("post_flistxattr: rejecting retval %lu > size %lu\n",
			  retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) retval <= 0)
		goto out_free;

	/*
	 * size=0 / NULL-buffer probe: retval is the required namebuffer
	 * size and the user buffer was not populated; the equality oracle
	 * would compare stale pool bytes against a real namebuffer and
	 * fire on every draw.
	 */
	if (snap->size == 0)
		goto out_free;

	if (snap->list == 0)
		goto out_free;

	snap_fd = (int) snap->arg1;
	if (snap_fd < 0)
		goto out_free;

	snap_len = (size_t) retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);
	/*
	 * Belt-and-braces: the sanitise-time clamp guarantees the kernel
	 * could not have written past snap->buf_alloc_size, so the retval
	 * never legitimately exceeds it.  Cap snap_len explicitly so a
	 * sibling-stomped rec->retval cannot turn the memcpy below into a
	 * read-OOB on the pool slot backing snap->list.
	 */
	if (snap->buf_alloc_size != 0 && snap_len > snap->buf_alloc_size)
		snap_len = snap->buf_alloc_size;

	if (!post_snapshot_or_skip(first_buf,
				   (void *)(unsigned long) snap->list,
				   snap_len))
		goto out_free;

	rc = syscall(SYS_flistxattr, snap_fd, recheck_buf, sizeof(recheck_buf));

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
		       "[oracle:flistxattr] fd=%d len=%zu first %s vs recheck %s\n",
		       snap_fd, snap_len, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.flistxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif /* SYS_flistxattr || __NR_flistxattr */

struct syscallentry syscall_flistxattr = {
	.name = "flistxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "list", [2] = "size" },
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
#if defined(SYS_flistxattr) || defined(__NR_flistxattr)
	.sanitise = sanitise_flistxattr,
	.post = post_flistxattr,
#endif
};

/*
 * SYSCALL_DEFINE3(listxattr, const char __user *, pathname, char __user *, list, size_t, size
 */
#if defined(SYS_listxattr) || defined(__NR_listxattr)
#ifndef SYS_listxattr
#define SYS_listxattr __NR_listxattr
#endif

static void sanitise_listxattr(struct syscallrecord *rec)
{
	struct listxattr_post_state *snap;
	unsigned long pre_a2;
	size_t buf_alloc_size;

	rec->post_state = 0;

	pre_a2 = rec->a2;
	xattr_pick_listbuf_bucket(&rec->a2, &rec->a3);
	avoid_shared_buffer_out(&rec->a2, rec->a3);

	/*
	 * Clamp rec->a3 (size) to the actual allocation backing rec->a2.
	 * See sanitise_flistxattr above for the full rationale and the
	 * 862ee5c6ae3a (sched_getattr) precedent -- identical pattern.
	 */
	if (rec->a2 != pre_a2)
		buf_alloc_size = rec->a3 > (unsigned long) page_size
				       ? (size_t) rec->a3
				       : (size_t) page_size;
	else
		buf_alloc_size = (size_t) page_size;

	if ((size_t) rec->a3 > buf_alloc_size)
		rec->a3 = (unsigned long) buf_alloc_size;

	/*
	 * Snapshot the pathname and list buffer pointer for the post
	 * oracle.  Without this the post handler reads rec->a1/a2 at
	 * post-time, when a sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user buffer pointer, so the memcpy /
	 * re-call would touch a foreign allocation.  post_state is private
	 * to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = LISTXATTR_POST_STATE_MAGIC;
	snap->arg1 = rec->a1;
	snap->list = rec->a2;
	snap->size = rec->a3;
	snap->buf_alloc_size = buf_alloc_size;
	post_state_install(rec, snap);
}

/*
 * Oracle: listxattr(path, list, size) walks `path`, resolves it to an
 * inode (following symlinks), and fills `list` with the NUL-separated
 * names of the extended attributes attached to that inode, returning
 * the byte length of the namebuffer written.  This is the path-walk
 * variant; unlike the fd-based flistxattr, it goes through the dcache
 * and mount namespace on every call, so it picks up dcache races and
 * rename/mount-shift effects in addition to the copy_to_user shapes.
 * Two back-to-back lookups of the same path from the same task --
 * assuming no sibling lsetxattr/lremovexattr or rename races in
 * between -- must produce a byte-identical name list of identical
 * length.  A divergence between the original syscall payload and an
 * immediate re-call points at one of:
 *
 *   - copy_to_user mis-write into the wrong user slot, leaving the
 *     original receive buffer torn (partial write, wrong-offset fill,
 *     residual stack data) while the re-call lands clean.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - 32-on-64 compat ABI truncating a size_t and shipping a short
 *     payload while reporting the full retval.
 *   - dcache race serving the second lookup a different inode for the
 *     same path string (rename/mount-shift between the two calls
 *     resolves the same name to a different file with a different
 *     xattr name set).
 *
 * TOCTOU defeat: both the path string (rec->a1) and the list buffer
 * (rec->a2) are snapshotted at sanitise time into a heap struct in
 * rec->post_state, so a sibling that scribbles rec->aN between syscall
 * return and post entry cannot redirect us at a foreign list buffer or
 * smear the path string the re-call walks.  We still snapshot the path
 * bytes and the first retval bytes of the receive buffer into stack-
 * locals BEFORE re-issuing, with a fresh private stack buffer for the
 * re-call (NOT the snapshot's list -- a sibling could mutate the user
 * buffer itself mid-syscall and forge a clean compare).  Drop the
 * sample if the re-call returns <= 0 (sibling unlinked the path or
 * cleared every xattr -- benign ENOENT/ENOATTR/0) or if it returns a
 * different length (sibling lsetxattr/lremovexattr changed the name
 * set -- benign size-class drift).  Compare exactly snap_len bytes
 * with memcmp; do not early-return on first divergence so a multi-
 * byte tear surfaces in a single sample, but bump the anomaly counter
 * only once.  Sample one in a hundred to stay in line with the rest
 * of the oracle family.
 *
 * On most fleets listxattr rarely returns a non-empty list (most
 * files have no xattrs) and the retval > 0 gate keeps this oracle
 * dormant; it costs ~zero on no-xattr hosts and protects niche
 * xattr-heavy ones.
 */
static void post_listxattr(struct syscallrecord *rec)
{
	struct listxattr_post_state *snap;
	unsigned long retval = rec->retval;
	char snap_path[4096];
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	snap = post_state_claim_owned(rec, LISTXATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) retval < 0)
		goto out_free;
	if (snap->size != 0 && retval > snap->size) {
		outputerr("post_listxattr: rejecting retval %lu > size %lu\n",
			  retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) retval <= 0)
		goto out_free;

	/*
	 * size=0 / NULL-buffer probe: retval is the required namebuffer
	 * size and the user buffer was not populated; skip the equality
	 * oracle so it does not compare stale pool bytes against a real
	 * namebuffer.
	 */
	if (snap->size == 0)
		goto out_free;

	if (snap->arg1 == 0 || snap->list == 0)
		goto out_free;

	if (!post_snapshot_str(snap_path, sizeof(snap_path),
			       (const char *)(unsigned long) snap->arg1))
		goto out_free;

	snap_len = (size_t) retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);
	/*
	 * Belt-and-braces: see sanitise_flistxattr's clamp -- snap_len is
	 * additionally bounded by the snapshotted allocation so a stomped
	 * rec->retval cannot turn the memcpy below into a read-OOB.
	 */
	if (snap->buf_alloc_size != 0 && snap_len > snap->buf_alloc_size)
		snap_len = snap->buf_alloc_size;

	if (!post_snapshot_or_skip(first_buf,
				   (void *)(unsigned long) snap->list,
				   snap_len))
		goto out_free;

	rc = syscall(SYS_listxattr, snap_path, recheck_buf,
		     sizeof(recheck_buf));

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
		       "[oracle:listxattr] path=%s len=%zu first %s vs recheck %s\n",
		       snap_path, snap_len, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.listxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif /* SYS_listxattr || __NR_listxattr */

struct syscallentry syscall_listxattr = {
	.name = "listxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "list", [2] = "size" },
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
#if defined(SYS_listxattr) || defined(__NR_listxattr)
	.sanitise = sanitise_listxattr,
	.post = post_listxattr,
#endif
};


/*
 * SYSCALL_DEFINE3(llistxattr, const char __user *, pathname, char __user *, list, size_t, size)
 */
#if defined(SYS_llistxattr) || defined(__NR_llistxattr)
#ifndef SYS_llistxattr
#define SYS_llistxattr __NR_llistxattr
#endif

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the fuzzer touches
 * (xattr-thrash, flock-thrash, fremovexattr, lremovexattr); cross-
 * process contention concentrates on the same per-inode i_xattrs rwsem.
 */
#define LLISTXATTR_NR_TESTFILES	4

/*
 * Curated name we plant ahead of the trinity-dispatched llistxattr.
 * user.* requires no privilege, is supported on every Linux fs that
 * carries xattrs, and matches the planted_xattr_name lremovexattr /
 * fremovexattr use so a single round of testfile xattrs is shared
 * across the whole xattr-family precondition surface.
 */
static const char llistxattr_planted_name[] = "user.trinity_plant";

/*
 * ARG_PATHNAME plumbed a random pathname into rec->a1, but the
 * random path is most often either not a real file at all
 * (ENOENT before the per-inode xattr list walk) or, even when
 * it does land on a real file, that inode has no xattrs --
 * vfs_listxattr returns 0 immediately, never touching the per-fs
 * handler dispatch or the simple_xattr_list walk that the
 * per-inode i_xattrs rwsem guards.  Same "high calls, low edges"
 * cold-syscall shape that the wall-lever shadow gate keeps re-
 * flagging, identical to the fremovexattr / lremovexattr profile
 * before their precondition fixes.
 *
 * Half the draws now repoint at one of the trinity-testfile<N>
 * absolute paths and plant a known user.* xattr there via
 * setxattr() so the subsequent llistxattr walks a non-empty
 * per-inode xattr list and reaches the real list-walk path.  The
 * other half preserves the slot exactly as the generic draw
 * left it, so the empty-list and ENOENT arms stay exercised.
 *
 * The plant runs BEFORE the listbuf bucket pick / clamp and
 * BEFORE the snapshot below so the snapshot captures the
 * (planted) rec->a1 -- the post oracle's re-call then re-walks
 * the planted path and compares its result against the first
 * call's payload exactly as the existing oracle expects.
 *
 * Slow-path note: the setxattr() in sanitise is one real
 * syscall.  syscalls/listxattr.c is outside the
 * sanitiser-slow-path check's FILES scope, so this is within
 * budget for the precondition payoff.
 */
static void sanitise_llistxattr_plant_pathname(struct syscallrecord *rec)
{
	char *path;

	if (rnd_modulo_u32(2) == 0) {
		path = get_testfile_path();
		if (path != NULL) {
			rec->a1 = (unsigned long) path;
			/*
			 * Plant a small opaque value.  Failure (ENOSPC,
			 * EOPNOTSUPP on a fs that bailed out of the user.*
			 * leg, ENOENT if the testfile slot was never
			 * opened, ...) is non-fatal: an earlier draw on
			 * the same inode may still hold a stale
			 * user.trinity_plant from a prior round, so
			 * llistxattr below may still see a non-empty list.
			 */
			(void) setxattr(path, llistxattr_planted_name,
					"trin", 4, 0);
		}
	}
}

/*
 * Buffer-size phase for rec->a2 (list) / rec->a3 (size).
 *
 * Clamp rec->a3 (size) to the actual allocation backing rec->a2.
 * See sanitise_flistxattr above for the full rationale and the
 * 862ee5c6ae3a (sched_getattr) precedent -- identical pattern.
 */
static size_t sanitise_llistxattr_size_buffer(struct syscallrecord *rec)
{
	unsigned long pre_a2;
	size_t buf_alloc_size;

	pre_a2 = rec->a2;
	xattr_pick_listbuf_bucket(&rec->a2, &rec->a3);
	avoid_shared_buffer_out(&rec->a2, rec->a3);

	if (rec->a2 != pre_a2)
		buf_alloc_size = rec->a3 > (unsigned long) page_size
				       ? (size_t) rec->a3
				       : (size_t) page_size;
	else
		buf_alloc_size = (size_t) page_size;

	if ((size_t) rec->a3 > buf_alloc_size)
		rec->a3 = (unsigned long) buf_alloc_size;

	return buf_alloc_size;
}

static void sanitise_llistxattr(struct syscallrecord *rec)
{
	struct listxattr_post_state *snap;
	size_t buf_alloc_size;

	rec->post_state = 0;

	sanitise_llistxattr_plant_pathname(rec);

	buf_alloc_size = sanitise_llistxattr_size_buffer(rec);

	/*
	 * Snapshot the pathname and list buffer pointer for the post
	 * oracle.  Without this the post handler reads rec->a1/a2 at
	 * post-time, when a sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original user buffer pointer, so the memcpy /
	 * re-call would touch a foreign allocation.  post_state is private
	 * to the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = LISTXATTR_POST_STATE_MAGIC;
	snap->arg1 = rec->a1;
	snap->list = rec->a2;
	snap->size = rec->a3;
	snap->buf_alloc_size = buf_alloc_size;
	post_state_install(rec, snap);
}

/*
 * Oracle: llistxattr(path, list, size) is the lstat-style sister of
 * listxattr -- it walks `path` WITHOUT following a terminal symlink,
 * so the inode it queries is the symlink itself (when one is present)
 * rather than its target.  That changes the TOCTOU surface in one
 * specific way: a sibling unlink/relink of the symlink between the
 * original return and our re-issue still resolves to the symlink
 * inode, but a sibling swap of the symlink target is now in scope as
 * a benign size-class drift cause -- swapping the target inode under
 * a stable symlink leaves llistxattr's view of the symlink xattr set
 * unchanged, but a parallel symlink replacement (unlink + symlink to
 * a different target) gives us a different terminal inode with a
 * potentially different xattr name set, and that drift is caught by
 * the snap_len mismatch gate exactly as for the path-walk variant.
 * Otherwise the failure modes mirror listxattr exactly:
 *
 *   - copy_to_user mis-write into the wrong user slot, leaving the
 *     original receive buffer torn (partial write, wrong-offset fill,
 *     residual stack data) while the re-call lands clean.
 *   - sibling-thread scribble of the user receive buffer between the
 *     original syscall return and our post-hook re-read.
 *   - 32-on-64 compat ABI truncating a size_t and shipping a short
 *     payload while reporting the full retval.
 *   - dcache race serving the second lookup a different inode for the
 *     same path string (rename/mount-shift, or symlink replacement,
 *     between the two calls resolves the same name to a different
 *     symlink inode with a different xattr name set).
 *
 * TOCTOU defeat: identical to listxattr -- the path string and list
 * buffer pointer are snapshotted at sanitise time into a heap struct
 * in rec->post_state, so a sibling that scribbles rec->aN between
 * syscall return and post entry cannot redirect us at a foreign list
 * buffer or smear the path string the re-call walks.  We still
 * snapshot the path bytes and the first retval bytes of the receive
 * buffer into stack-locals before re-issuing, with a fresh private
 * stack buffer for the re-call (NOT the snapshot's list -- a sibling
 * could mutate the user buffer itself mid-syscall and forge a clean
 * compare).  Drop on rc <= 0 or length mismatch, memcmp exactly
 * snap_len bytes without early-return so multi-byte tears surface in
 * a single sample, bump the anomaly counter once.  Sample one in a
 * hundred to stay in line with the rest of the oracle family.
 *
 * On most fleets llistxattr rarely returns a non-empty list (most
 * symlinks have no xattrs) and the retval > 0 gate keeps this oracle
 * dormant; it costs ~zero on no-xattr hosts and protects niche
 * xattr-heavy ones.
 */
static void post_llistxattr(struct syscallrecord *rec)
{
	struct listxattr_post_state *snap;
	unsigned long retval = rec->retval;
	char snap_path[4096];
	unsigned char first_buf[4096];
	unsigned char recheck_buf[4096];
	size_t snap_len;
	long rc;

	snap = post_state_claim_owned(rec, LISTXATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) retval < 0)
		goto out_free;
	if (snap->size != 0 && retval > snap->size) {
		outputerr("post_llistxattr: rejecting retval %lu > size %lu\n",
			  retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) retval <= 0)
		goto out_free;

	/* size=0 / NULL-buffer probe -- see post_listxattr for full rationale. */
	if (snap->size == 0)
		goto out_free;

	if (snap->arg1 == 0 || snap->list == 0)
		goto out_free;

	if (!post_snapshot_str(snap_path, sizeof(snap_path),
			       (const char *)(unsigned long) snap->arg1))
		goto out_free;

	snap_len = (size_t) retval;
	if (snap_len > sizeof(first_buf))
		snap_len = sizeof(first_buf);
	/*
	 * Belt-and-braces: see sanitise_flistxattr's clamp -- snap_len is
	 * additionally bounded by the snapshotted allocation so a stomped
	 * rec->retval cannot turn the memcpy below into a read-OOB.
	 */
	if (snap->buf_alloc_size != 0 && snap_len > snap->buf_alloc_size)
		snap_len = snap->buf_alloc_size;

	if (!post_snapshot_or_skip(first_buf,
				   (void *)(unsigned long) snap->list,
				   snap_len))
		goto out_free;

	rc = syscall(SYS_llistxattr, snap_path, recheck_buf,
		     sizeof(recheck_buf));

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
		       "[oracle:llistxattr] path=%s len=%zu first %s vs recheck %s\n",
		       snap_path, snap_len, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.llistxattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif /* SYS_llistxattr || __NR_llistxattr */

struct syscallentry syscall_llistxattr = {
	.name = "llistxattr",
	.num_args = 3,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "list", [2] = "size" },
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
#if defined(SYS_llistxattr) || defined(__NR_llistxattr)
	.sanitise = sanitise_llistxattr,
	.post = post_llistxattr,
#endif
};
