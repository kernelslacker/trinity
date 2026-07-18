/*
 * SYSCALL_DEFINE5(file_getattr, int, dfd, const char __user *, filename,
 *		struct file_attr __user *, ufattr, size_t, usize,
 *		unsigned int, at_flags)
 */
#include <limits.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "arch.h"
#include "output-poison.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/fs.h"
/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the path-pinned
 * sanitisers (chmod, utime, utimensat, xattr-thrash, ...) touch;
 * cross-process contention concentrates on the same per-inode i_rwsem /
 * vfs_fileattr_get path.
 */
#define NR_TESTFILES 4

#if defined(SYS_file_getattr) || defined(__NR_file_getattr)
#ifndef SYS_file_getattr
#define SYS_file_getattr __NR_file_getattr
#endif
#define HAVE_SYS_FILE_GETATTR 1
#endif

static unsigned long file_getattr_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

#ifdef HAVE_SYS_FILE_GETATTR
/*
 * Snapshot of the five file_getattr input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect us at a foreign ufattr, cannot flip
 * the dfd, and cannot smear the usize bound or the at_flags lookup mode
 * used to seed the re-issue.  The pathname is snapshotted by VALUE into
 * the embedded byte buffer below rather than by pointer -- a stale
 * heap-shaped pathname pointer that survived looks_like_corrupted_ptr's
 * shape-only gate would otherwise let the .post strncpy walk off the
 * end of an unrelated allocation, and a sibling rewrite of the bytes
 * between sanitise and post would steer the re-call at a different
 * inode than the one the original syscall actually resolved.
 */
#define FILE_GETATTR_POST_STATE_MAGIC	0x46474154UL	/* "FGAT" */
#define FILE_GETATTR_POISON_SEED	0x4641545452505354ULL	/* "FATTRPST" */
struct file_getattr_post_state {
	unsigned long magic;
	unsigned long dfd;
	unsigned long ufattr;
	unsigned long usize;
	unsigned long at_flags;
	size_t buf_alloc_size;
	uint64_t poison_seed;
	char pathname[PATH_MAX];
};
#endif

/*
 * Bias at_flags (rec->a5) toward the kernel's allowlist:
 *
 *   if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
 *           return -EINVAL;
 *
 * handle_arg_list ORs in shift_flag_bit() / CMP-hint bits for
 * adjacent-bit probing on ~3/16 of calls; any bit outside the
 * two-flag allowlist bounces the call straight back with -EINVAL
 * before the lookup runs.  Mask the noise off ~7/8 of the time
 * so the call reaches filename_lookup(); ~1/8 leaves the OR'd
 * noise intact so the reject path stays covered.  The mask only
 * trims foreign bits -- the underlying ARG_LIST pick across
 * {0, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH, both} is preserved.
 */
static void mask_file_getattr_at_flags(struct syscallrecord *rec)
{
	if (!ONE_IN(8))
		rec->a5 &= (unsigned long)
			   (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);
}

#ifdef HAVE_SYS_FILE_GETATTR
/*
 * Snapshot input state for the post oracle.  Without this the
 * post handler reads rec->a1..a5 at post-time, when a sibling
 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
 * cannot tell a real-but-wrong heap address from the original
 * user ufattr pointer, so the memcpy / re-issue would touch a
 * foreign allocation, a stomped usize or at_flags word would
 * smear the comparison bound or change the lookup mode, and a
 * stale rec->a2 / sibling-rewritten pathname bytes would let the
 * re-issue resolve a different inode.  Snapshot the pathname
 * BYTES via post_snapshot_str so the post handler never re-derefs
 * the user pointer; skip the post sample when the snapshot source
 * is not provably readable.  post_state is private to the post
 * handler.  Gated on HAVE_SYS_FILE_GETATTR to mirror the .post
 * body -- on systems without SYS_file_getattr the post handler is
 * a no-op stub and a snapshot only the post handler can free
 * would leak.
 */
static void snapshot_file_getattr_state(struct syscallrecord *rec,
					size_t buf_alloc_size)
{
	struct file_getattr_post_state *snap;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = FILE_GETATTR_POST_STATE_MAGIC;
	snap->dfd      = rec->a1;
	snap->ufattr   = rec->a3;
	snap->usize    = rec->a4;
	snap->at_flags = rec->a5;
	snap->buf_alloc_size = buf_alloc_size;
	snap->poison_seed = 0;
	if (!post_snapshot_str(snap->pathname, sizeof(snap->pathname),
			       (const char *)(unsigned long) rec->a2))
		snap->pathname[0] = '\0';

	/*
	 * Stamp a fixed poison pattern into the FILE_ATTR_SIZE_VER0 window
	 * the kernel is guaranteed to fully overwrite on a retval==0 return
	 * (usize was clamped >= VER0 by the biased draw above, and any usize
	 * < VER0 bounces on -EINVAL before touching the buffer).  The post
	 * handler asks check_output_struct_user_or_skip() whether the prefix
	 * survived intact on a success return; a match means the kernel
	 * reported success without ever calling copy_to_user -- the same
	 * untouched-out-buffer signal lstat's LSTAT_POISON_SZ oracle surfaces,
	 * bounded to the guaranteed-written prefix so an unwritten padding
	 * tail cannot false-positive.  Pattern is a fixed non-zero magic
	 * (not rnd_u64()) so the sanitise pass draws no RNG bytes on this
	 * leg: --dry-run output with a fixed seed stays byte-identical to a
	 * build without this oracle, keeping cross-tree replays and fixed-
	 * seed corpus regeneration unaffected.  Guard on buf_alloc_size >=
	 * VER0 so a pool draw smaller than the ver0 window (rare, the
	 * sanitise resolver conservatively caps at page_size) does not
	 * overrun the allocation, and range_readable_user() so a writable-
	 * pool draw that avoid_shared_buffer_out moved to an address no
	 * longer provably mapped does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk.  On skip poison_seed stays 0
	 * and the post handler no-ops the untouched-buffer arm; the
	 * ONE_IN(100) re-issue oracle below is unaffected either way.
	 */
	if (rec->a3 != 0 && buf_alloc_size >= FILE_ATTR_SIZE_VER0 &&
	    range_readable_user((void *)(unsigned long) rec->a3,
				FILE_ATTR_SIZE_VER0))
		snap->poison_seed = poison_output_struct(
			(void *)(unsigned long) rec->a3,
			FILE_ATTR_SIZE_VER0, FILE_GETATTR_POISON_SEED);

	post_state_install(rec, snap);
}
#endif

static void sanitise_file_getattr(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_FILE_GETATTR
	unsigned long pre_a3;
	size_t buf_alloc_size;

	rec->post_state = 0;

	pre_a3 = rec->a3;
#endif

	/*
	 * Bias usize (rec->a4) toward the kernel's valid window so the
	 * call reaches the FS-attr read path instead of bouncing on early
	 * validation:
	 *
	 *   if (usize > PAGE_SIZE)            return -E2BIG;
	 *   if (usize < FILE_ATTR_SIZE_VER0)  return -EINVAL;
	 *
	 * ARG_LEN -> get_len() draws across 0..UINT_MAX with boundary
	 * picks (UINT_MAX, 0, page_size-1, sizeof(char/short/int/long)),
	 * almost none of which land in [FILE_ATTR_SIZE_VER0, page_size].
	 * The pre-bias rate of falling through to vfs_fileattr_get() is
	 * ~3% of calls and the syscall surfaces only a handful of edges
	 * as a result.  Rewrite ~7/8 of calls to a valid size -- half
	 * pinned at the canonical FILE_ATTR_SIZE_VER0 a real userspace
	 * caller would pass, half uniform across [VER0, page_size) --
	 * and leave ~1/8 at whatever get_len() picked so the rejection
	 * paths (undersize -EINVAL, oversize -E2BIG) stay covered.
	 *
	 * The buffer-bounded usize clamp below still runs unchanged on
	 * the biased value so it can never exceed the allocation backing
	 * rec->a3 (preserves the kernel write-OOB guard from
	 * 862ee5c6ae3a).  Mirrors the pattern at the top of
	 * sanitise_sched_getattr.
	 */
	if (!ONE_IN(8)) {
		if (RAND_BOOL()) {
			rec->a4 = (unsigned long) FILE_ATTR_SIZE_VER0;
		} else {
			unsigned long range = (unsigned long) page_size -
					      FILE_ATTR_SIZE_VER0;

			rec->a4 = rnd_modulo_u32(range) + FILE_ATTR_SIZE_VER0;
		}
	}

	mask_file_getattr_at_flags(rec);

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2, but the
	 * random path is most often not a real file at all -- file_getattr
	 * returns ENOENT at the path walk before ever reaching
	 * vfs_fileattr_get / the per-fs ->fileattr_get, and the
	 * post_file_getattr byte-identity oracle bails out on the non-zero
	 * retval so it almost never fires.
	 *
	 * Half the draws repoint a2 at one of the trinity-testfile<N>
	 * absolute paths so the subsequent call lands on a real
	 * trinity-owned inode and penetrates filename_lookup() into
	 * vfs_fileattr_get -- the post oracle then re-issues against the
	 * same inode and compares struct file_attr byte-for-byte.  The
	 * absolute path means the kernel ignores the random dfd and walks
	 * from root, so the pin works regardless of which fd dfd resolved
	 * to.  The other half preserves the slot as the generic draw left
	 * it so the ENOENT reject arm stays exercised.  Read-only -- no
	 * mutation of the testfile contents, zero pool risk.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL)
			rec->a2 = (unsigned long) path;
	}

	avoid_shared_buffer_out(&rec->a3, rec->a4);

#ifdef HAVE_SYS_FILE_GETATTR
	/*
	 * Resolve the actual allocation size of the buffer at rec->a3:
	 *
	 *   - If avoid_shared_buffer_out() redirected (the pointer
	 *     changed), the replacement came from get_writable_address(rec->a4)
	 *     which guarantees a region of at least max(rec->a4, page_size)
	 *     bytes (get_writable_address falls back to page_size for a 0
	 *     length, and every backing pool slot is at least page_size).
	 *   - Otherwise rec->a3 is still the pool pointer the generator
	 *     handed us via gen_arg_non_null_address() / get_address(),
	 *     which routes through get_writable_address(RAND_ARRAY(
	 *     mapping_sizes)).  mapping_sizes[0] == page_size, so the
	 *     slot is provably at least page_size bytes; we cannot prove
	 *     more than that without re-resolving the slot, so use
	 *     page_size as the conservative bound.
	 *
	 * Mirrors the resolution pattern from sched_getattr's clamp
	 * (862ee5c6ae3a) but for the pool-backed ARG_NON_NULL_ADDRESS
	 * buffer family rather than the catalog-backed ARG_STRUCT_PTR_OUT
	 * family.
	 */
	if (rec->a3 != pre_a3)
		buf_alloc_size = rec->a4 > (unsigned long) page_size
				       ? (size_t) rec->a4
				       : (size_t) page_size;
	else
		buf_alloc_size = (size_t) page_size;

	/*
	 * Clamp the size argument the kernel sees to the buffer's actual
	 * allocation.  rec->a4 (usize) comes from ARG_LEN via generic_sanitise
	 * -- get_len() returns boundary values including UINT_MAX, sizeof-
	 * boundary values, and page_size-1 -- chosen independently of the
	 * buffer at rec->a3.  When fuzz picks a usize larger than the buffer
	 * the generator handed the kernel, the kernel's copy_to_user writes
	 * min(usize, sizeof(struct file_attr)) bytes and overruns the live
	 * allocation into adjacent heap-arena or pool-neighbour objects --
	 * the same kernel write-OOB shape the sched_getattr clamp
	 * (862ee5c6ae3a) closed for sched_attr.  Bounding usize at sanitise
	 * time preserves the freedom to fuzz across the buffer-bounded range
	 * while keeping the kernel's write inside the allocation.
	 */
	if ((size_t) rec->a4 > buf_alloc_size)
		rec->a4 = (unsigned long) buf_alloc_size;

	snapshot_file_getattr_state(rec, buf_alloc_size);
#endif
}

/*
 * Oracle: file_getattr(dfd, filename, ufattr, usize, at_flags) writes a
 * struct file_attr describing the inode's filesystem-attribute flags
 * (xflags: immutable, append, sync, no_atime, no_dump, ...; extsize;
 * project id; cow extsize; nextents) into the user buffer.  Every field
 * lives on the inode and is stable across the ~150ms window between the
 * original syscall return and our post-hook re-call -- the only legitimate
 * mutator is a chattr(1)/FS_IOC_FSSETXATTR-class operation, which a sibling
 * trinity child could fire but is rare enough that any divergence we see is
 * far more likely to be one of:
 *
 *   - copy_to_user mis-write that leaves a torn struct file_attr in user
 *     memory (partial write, wrong-offset fill, residual stack data).
 *   - 32-bit-on-64-bit compat sign-extension on the size_t usize word.
 *   - struct-layout mismatch shifting fa_xflags into the fa_extsize slot,
 *     or fa_projid into fa_cowextsize, on a kernel/glibc skew.
 *   - sibling-thread scribble of the user receive buffer between syscall
 *     return and our post-hook re-read.
 *
 * TOCTOU defeat (five buffers worth of it): the dfd, pathname, ufattr,
 * usize, and at_flags args are snapshotted at sanitise time into a heap
 * struct in rec->post_state, so a sibling that scribbles rec->aN between
 * syscall return and post entry cannot retarget the dfd, redirect the
 * strncpy at a foreign pathname, steer the memcpy at a foreign ufattr,
 * smear the usize comparison bound, or flip at_flags between the
 * original lookup mode and the re-issue.  The pathname is the dominant
 * attack surface -- alloc_shared can hand it to another child which
 * then scribbles it; the snap captures the pointer the kernel actually
 * resolved on the original call.  We still copy the path into a
 * PATH_MAX stack buffer and the first usize bytes of the original
 * file_attr into a stack-local before re-calling, so a sibling that
 * scribbles the user buffers themselves between the two reads cannot
 * smear the comparison.  Re-issue with FRESH private buffers (do NOT
 * pass the snap's ufattr -- a sibling could mutate the user buffer
 * mid-syscall and forge a clean compare).  If the re-call fails, give
 * up rather than report (file may have been unlinked by sibling between
 * calls).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  A real chattr-race divergence is itself an interesting TOCTOU
 * we want to surface; the ONE_IN(100) sampling keeps signal alive without
 * flooding the channel.
 */
static void post_file_getattr(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_FILE_GETATTR
	struct file_getattr_post_state *snap;
	struct file_attr first_attr;
	struct file_attr recheck_attr;
	size_t usize;
	unsigned int at_flags;
	int dfd;
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, FILE_GETATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Untouched-out-buffer check: on every retval==0 return, verify the
	 * FILE_ATTR_SIZE_VER0 poison prefix stamped at sanitise time did NOT
	 * survive intact.  A match means the kernel reported success without
	 * copy_to_user'ing anything into the buffer -- a torn write, a "return
	 * 0 before fill" early-exit, or a mis-wired compat wrapper.  O(24)
	 * memcmp against a fixed pattern, no re-issue, so runs on every
	 * success rather than the ONE_IN(100) sample used by the heavier
	 * field-divergence oracle below.  Skips silently when the sanitiser
	 * refused to stamp (poison_seed == 0) or ufattr was NULL, and the
	 * check_output_struct_user_or_skip helper folds in the post_snapshot
	 * TOCTOU guard against sibling munmap of the pool page mid-check.
	 */
	if ((long) rec->retval == 0 && snap->ufattr != 0 &&
	    snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip(
		    (void *)(unsigned long) snap->ufattr,
		    FILE_ATTR_SIZE_VER0, snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	if ((long) rec->retval != 0)
		goto out_release;

	if (snap->ufattr == 0)
		goto out_release;

	if (snap->pathname[0] == '\0')
		goto out_release;

	usize = (size_t) snap->usize;
	if (usize < sizeof(struct file_attr))
		goto out_release;
	if (usize > sizeof(struct file_attr))
		usize = sizeof(struct file_attr);
	/*
	 * Belt-and-braces: the sanitise-time clamp guarantees snap->usize
	 * <= snap->buf_alloc_size, but a sibling that scribbled snap->usize
	 * could push it past the actual allocation backing snap->ufattr.
	 * The memcpy below reads `usize` bytes from snap->ufattr; bound it
	 * by the snapshotted allocation size so a stomped snap->usize
	 * cannot turn the oracle's source memcpy into a read-OOB on the
	 * pool slot.
	 */
	if (snap->buf_alloc_size != 0 && usize > snap->buf_alloc_size)
		usize = snap->buf_alloc_size;
	if (usize < sizeof(struct file_attr))
		goto out_release;

	dfd = (int) snap->dfd;
	at_flags = (unsigned int) snap->at_flags;

	if (!post_snapshot_or_skip(&first_attr,
				   (const void *) snap->ufattr, usize))
		goto out_release;

	memset(&recheck_attr, 0, sizeof(recheck_attr));
	rc = syscall(SYS_file_getattr, dfd, snap->pathname, &recheck_attr,
		     sizeof(recheck_attr), at_flags);
	if (rc != 0)
		goto out_release;

	if (memcmp(&first_attr, &recheck_attr, usize) != 0) {
		const unsigned char *first_bytes = (const unsigned char *) &first_attr;
		const unsigned char *recheck_bytes = (const unsigned char *) &recheck_attr;
		char first_hex[8 * 3 + 1];
		char recheck_hex[8 * 3 + 1];
		size_t off;
		unsigned int i;

		off = 0;
		for (i = 0; i < 8; i++)
			off += snprintf(first_hex + off, sizeof(first_hex) - off,
					"%02x ", first_bytes[i]);
		first_hex[off > 0 ? off - 1 : 0] = '\0';

		off = 0;
		for (i = 0; i < 8; i++)
			off += snprintf(recheck_hex + off, sizeof(recheck_hex) - off,
					"%02x ", recheck_bytes[i]);
		recheck_hex[off > 0 ? off - 1 : 0] = '\0';

		output(0,
		       "[oracle:file_getattr] dfd=%d path=%s usize=%zu [%s] vs [%s]\n",
		       dfd, snap->pathname, usize, first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.oracle.file_getattr_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_file_getattr = {
	.name = "file_getattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_NON_NULL_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "ufattr", [3] = "usize", [4] = "at_flags" },
	.arg_params[4].list = ARGLIST(file_getattr_at_flags),
	.sanitise = sanitise_file_getattr,
	.post = post_file_getattr,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_VFS,
};
