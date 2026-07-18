/*
 * SYSCALL_DEFINE5(listxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, char __user *, list, size_t, size)
 */
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <linux/limits.h>
#include <fcntl.h>
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

#include "kernel/fcntl.h"
/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the xattr-family
 * (getxattr, lgetxattr, fgetxattr, getxattrat, fremovexattr,
 * lremovexattr, llistxattr, listxattr) touches; cross-process contention
 * concentrates on the same per-inode i_xattrs rwsem.
 */
#define LISTXATTRAT_NR_TESTFILES	4

/*
 * Curated name we plant ahead of the trinity-dispatched listxattrat.
 * user.* requires no privilege, is supported on every Linux fs that
 * carries xattrs, and matches the planted_xattr_name the rest of the
 * xattr-family precondition surface uses so a single round of testfile
 * xattrs is shared across the whole family.
 */
static const char listxattrat_planted_name[] = "user.trinity_plant";

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
#define LISTXATTRAT_POST_STATE_MAGIC	0x4C53584154544154UL	/* "LSXATTAT" */
struct listxattrat_post_state {
	unsigned long magic;
	unsigned long dfd;
	unsigned long pathname;
	unsigned long at_flags;
	unsigned long list;
	unsigned long size;
	size_t buf_alloc_size;
};
#endif

/*
 * ARG_PATHNAME plumbed a random pathname into rec->a2, but the
 * random path is most often either not a real file at all
 * (ENOENT before the per-inode xattr list walk) or, even when
 * it does land on a real file, that inode has no xattrs --
 * vfs_listxattr returns a 0-length name list immediately, never
 * reaching the per-fs handler dispatch or the simple_xattr_list
 * walk that the per-inode i_xattrs rwsem guards.  Same "high
 * calls, low edges" cold-syscall shape that the rest of the
 * xattr family was in before their precondition fixes.
 *
 * Half the draws now repoint pathname (a2) at one of the
 * trinity-testfile<N> absolute paths and plant a known user.*
 * xattr there via setxattr() so the subsequent listxattrat
 * walks a non-empty per-inode xattr list and reaches the real
 * list-walk path.  An absolute pathname makes dfd irrelevant --
 * the kernel ignores rec->a1 when pathname is absolute -- so
 * this composes cleanly with the AT_FDCWD-pin / random-fd dfd
 * logic and the at_flags sanitiser below; the planted testfiles
 * are regular files so AT_SYMLINK_NOFOLLOW is a no-op on them,
 * and the absolute non-empty path makes AT_EMPTY_PATH
 * irrelevant too.  The other half preserves rec->a2 exactly as
 * the generic draw left it so the empty-list / ENOENT arms
 * stay exercised.
 *
 * The plant runs BEFORE the post-state snapshot below so
 * snap->pathname captures the planted byte sequence -- the post
 * oracle's re-call then re-walks the planted path and compares
 * its returned name list against the first call's payload
 * exactly as the existing oracle expects.  Plant failure
 * (ENOSPC on a full xattr list, EOPNOTSUPP on a fs that bailed
 * out of the user.* leg, ENOENT if the testfile slot was never
 * opened, ...) is non-fatal: an earlier draw on the same inode
 * may still hold a stale user.trinity_plant from a prior round,
 * so listxattrat below may still see a non-empty list.
 *
 * Slow-path note: the setxattr() in sanitise is one real
 * syscall.  syscalls/listxattrat.c is outside the
 * sanitiser-slow-path check's FILES scope, so this is within
 * budget for the precondition payoff.
 */
static void sanitise_listxattrat_plant_pathname(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL) {
			rec->a2 = (unsigned long) path;
			(void) setxattr(path, listxattrat_planted_name,
					"trin", 4, 0);
		}
	}
}

#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
/*
 * Buffer-size phase for rec->a4 (list) / rec->a5 (size).
 *
 * Buffer-size legality buckets: substitute (buf, size) with a
 * curated boundary pair on ~half of all draws.  See xattr.c for
 * the bucket list.  Called before avoid_shared_buffer_out so the
 * existing pre/post comparison correctly classifies a substituted
 * buffer.
 *
 * Resolve the actual allocation size of the buffer at rec->a4 and
 * clamp rec->a5 (size) to it before the kernel sees the syscall.
 * rec->a5 comes from ARG_LEN / get_len() which freely returns
 * UINT_MAX-class values picked independently of the pool slot at
 * rec->a4.  The kernel's vfs_listxattr writes min(size, name_list_len)
 * bytes into the user buffer; when size > the live allocation the
 * write spills into adjacent heap-arena / pool-neighbour objects
 * and corrupts glibc chunk metadata, with the abort surfacing far
 * downstream (deferred_free_flush, _int_malloc on a corrupted
 * tcache, etc.).  Same shape as the sched_getattr clamp
 * (862ee5c6ae3a), applied here to the pool-backed ARG_ADDRESS
 * buffer family.
 *
 *   - If avoid_shared_buffer_out() redirected (pointer changed),
 *     the replacement came from get_writable_address(rec->a5) and
 *     is at least max(rec->a5, page_size) bytes.
 *   - Otherwise rec->a4 is the original ARG_ADDRESS pool slot from
 *     get_address() -> get_writable_address(RAND_ARRAY(
 *     mapping_sizes)); mapping_sizes[0] == page_size so the slot
 *     is provably at least page_size bytes, the conservative bound
 *     we can prove without re-resolving the slot.
 */
static size_t sanitise_listxattrat_size_buffer(struct syscallrecord *rec)
{
	unsigned long pre_a4;
	size_t buf_alloc_size;

	pre_a4 = rec->a4;

	xattr_pick_listbuf_bucket(&rec->a4, &rec->a5);

	avoid_shared_buffer_out(&rec->a4, rec->a5);

	if (rec->a4 != pre_a4)
		buf_alloc_size = rec->a5 > (unsigned long) page_size
				       ? (size_t) rec->a5
				       : (size_t) page_size;
	else
		buf_alloc_size = (size_t) page_size;

	if ((size_t) rec->a5 > buf_alloc_size)
		rec->a5 = (unsigned long) buf_alloc_size;

	return buf_alloc_size;
}
#endif

static void sanitise_listxattrat(struct syscallrecord *rec)
{
#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
	struct listxattrat_post_state *snap;
	size_t buf_alloc_size;

	rec->post_state = 0;
#endif

	sanitise_listxattrat_plant_pathname(rec);

#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
	buf_alloc_size = sanitise_listxattrat_size_buffer(rec);
#else
	/*
	 * Buffer-size legality buckets: substitute (buf, size) with a
	 * curated boundary pair on ~half of all draws.  See xattr.c for
	 * the bucket list.  Called before avoid_shared_buffer_out so the
	 * existing pre/post comparison correctly classifies a substituted
	 * buffer.
	 */
	xattr_pick_listbuf_bucket(&rec->a4, &rec->a5);

	avoid_shared_buffer_out(&rec->a4, rec->a5);
#endif

#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
	/*
	 * at_flags (a3): handle_arg_list's 1/8 shift_flag_bit and 1/16
	 * cmp-hint paths regularly OR in bits outside the kernel-accepted
	 * (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) mask, and path_listxattrat
	 * rejects those with -EINVAL before any xattr-list work runs.
	 * Drop the stray bits on 7/8 of draws so the rejected fraction
	 * stays meaningful for reject-path coverage but does not dominate
	 * the call mix.
	 */
	if (!ONE_IN(8))
		rec->a3 &= (unsigned long)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);

	/*
	 * dfd (a1): ARG_FD draws from the full fd pool (regular files,
	 * pipes, sockets, ...).  When pathname is relative the kernel
	 * does a dir-relative lookup against dfd and a non-directory fd
	 * is rejected with -ENOTDIR before VFS-level xattr work.  Pin
	 * to AT_FDCWD on 1/3 of draws so the relative-path fraction
	 * lands on a usable base while leaving the random-fd path well
	 * exercised for the dfd-only (AT_EMPTY_PATH + NULL pathname)
	 * shape.
	 */
	if (ONE_IN(3))
		rec->a1 = (unsigned long)(long) AT_FDCWD;

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
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = LISTXATTRAT_POST_STATE_MAGIC;
	snap->dfd      = rec->a1;
	snap->pathname = rec->a2;
	snap->at_flags = rec->a3;
	snap->list     = rec->a4;
	snap->size     = rec->a5;
	snap->buf_alloc_size = buf_alloc_size;
	post_state_install(rec, snap);
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
	struct listxattrat_post_state *snap;
	unsigned long retval = rec->retval;
	int snap_dfd;
	char snap_path[PATH_MAX];
	unsigned int snap_at_flags;
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
	snap = post_state_claim_owned(rec, LISTXATTRAT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * STRONG-VAL count bound: listxattrat(2) on success returns the
	 * byte length of the NUL-separated name list written into `list`,
	 * a value capped at the `size` argument by the VFS.  Failure
	 * returns -1UL.  A retval > size on a non-(-1UL) return is a
	 * structural ABI regression -- sign-extension tear in the return
	 * slot, sibling-stomp of rec->retval between syscall return and
	 * post entry, or -errno leaking through the success slot.  Compare
	 * against the snapshotted size (snap->size) rather than rec->a5 so
	 * a sibling that scribbles rec->aN between syscall return and post
	 * entry cannot launder an oversized retval past this gate.  Fires
	 * unconditionally, ahead of the ONE_IN(100) sample gate, so every
	 * offending retval is counted.
	 */
	if ((long) retval != -1L && snap->size != 0 &&
	    retval > snap->size) {
		outputerr("post_listxattrat: rejected retval=0x%lx > size=%lu\n",
			  retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) retval <= 0)
		goto out_free;

	/*
	 * size=0 probe: retval is the required namebuffer size and the
	 * user buffer was not populated -- the equality oracle would
	 * compare stale pool bytes against a real namebuffer.
	 */
	if (snap->size == 0)
		goto out_free;

	if (snap->list == 0)
		goto out_free;

	if (snap->pathname == 0)
		goto out_free;

	snap_dfd = (int) snap->dfd;
	snap_at_flags = (unsigned int) snap->at_flags;

	if (!post_snapshot_str(snap_path, sizeof(snap_path),
			       (const char *)(unsigned long) snap->pathname))
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
		__atomic_add_fetch(&shm->stats.oracle.listxattrat_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif /* SYS_listxattrat || __NR_listxattrat */

struct syscallentry syscall_listxattrat = {
	.name = "listxattrat",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_ADDRESS, [4] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "list", [4] = "size" },
	.arg_params[2].list = ARGLIST(listxattrat_at_flags),
	.sanitise = sanitise_listxattrat,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
#if defined(SYS_listxattrat) || defined(__NR_listxattrat)
	.post = post_listxattrat,
#endif
};
