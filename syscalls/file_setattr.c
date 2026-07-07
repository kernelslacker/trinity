/*
 * SYSCALL_DEFINE5(file_setattr, int, dfd, const char __user *, filename,
 *		struct file_attr __user *, ufattr, size_t, usize,
 *		unsigned int, at_flags)
 */
#include <fcntl.h>
#include <linux/fs.h>
#include "csfu.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

#include "kernel/fcntl.h"
#include "kernel/fs.h"
static unsigned long file_setattr_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

/*
 * Curated FS_XFLAG_* bits accepted by vfs_fileattr_set().  Even with a
 * zero-filled csfu buffer fa->fa_xflags starts at 0 (which the kernel
 * accepts but exercises nothing interesting); a random u32 would
 * almost always carry bits outside FS_XFLAGS_MASK and bounce on
 * -EINVAL before reaching the real fileattr_set arm.  Seed fa_xflags
 * from a curated pool of valid FS_XFLAG_* bits instead so the
 * interesting setattr paths actually get reached.
 */
static const unsigned long file_setattr_xflag_pool[] = {
	FS_XFLAG_REALTIME, FS_XFLAG_PREALLOC, FS_XFLAG_IMMUTABLE,
	FS_XFLAG_APPEND, FS_XFLAG_SYNC, FS_XFLAG_NOATIME, FS_XFLAG_NODUMP,
	FS_XFLAG_RTINHERIT, FS_XFLAG_PROJINHERIT, FS_XFLAG_NOSYMLINKS,
	FS_XFLAG_EXTSIZE, FS_XFLAG_EXTSZINHERIT, FS_XFLAG_NODEFRAG,
	FS_XFLAG_FILESTREAM, FS_XFLAG_DAX, FS_XFLAG_COWEXTSIZE,
	FS_XFLAG_VERITY, FS_XFLAG_CASEFOLD, FS_XFLAG_CASENONPRESERVING,
	FS_XFLAG_HASATTR,
};

#define FILE_SETATTR_XFLAG_POOL_MASK					\
	(FS_XFLAG_REALTIME | FS_XFLAG_PREALLOC | FS_XFLAG_IMMUTABLE |	\
	 FS_XFLAG_APPEND | FS_XFLAG_SYNC | FS_XFLAG_NOATIME |		\
	 FS_XFLAG_NODUMP | FS_XFLAG_RTINHERIT | FS_XFLAG_PROJINHERIT |	\
	 FS_XFLAG_NOSYMLINKS | FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT |\
	 FS_XFLAG_NODEFRAG | FS_XFLAG_FILESTREAM | FS_XFLAG_DAX |	\
	 FS_XFLAG_COWEXTSIZE | FS_XFLAG_VERITY | FS_XFLAG_CASEFOLD |	\
	 FS_XFLAG_CASENONPRESERVING | FS_XFLAG_HASATTR)

/*
 * Single-version ABI today: struct file_attr has only one published
 * layout, so there is no pre-ksize ABI floor to seed the UNDERSIZE
 * bucket from -- it draws from [0, ksize).  Mirrors the setxattrat
 * descriptor; if the kernel ever grows a VER1, add a known_sizes[].
 */
static const struct csfu_desc desc_file_setattr = {
	.name = "file_attr",
	.ksize = sizeof(struct file_attr),
};

static void sanitise_file_setattr(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_file_setattr);
	struct file_attr *fa = buf.ptr;

	if (fa == NULL)
		return;

	/*
	 * Non-EXACT buckets are rejected on usize by copy_struct_from_user()
	 * before the kernel reads fa->fa_xflags, so populating body fields
	 * there is wasted work; OVERSIZE_NONZERO and TAIL_MISMATCH
	 * specifically want their tail garbage preserved.  The
	 * zmalloc_tracked() buffer is already zeroed where the kernel
	 * cares to look.
	 */
	if (buf.bucket == CSFU_BUCKET_EXACT) {
		unsigned long long xflags = 0;
		unsigned int n_bits;
		unsigned int i;

		/* OR 1..3 bits drawn from the curated pool. */
		n_bits = 1 + rnd_modulo_u32(3);
		for (i = 0; i < n_bits; i++)
			xflags |= file_setattr_xflag_pool[
				rnd_modulo_u32(ARRAY_SIZE(file_setattr_xflag_pool))];

		/*
		 * ~5%: also OR in an outside-mask u32 so the
		 * vfs_fileattr_set() rejection arm gets exercised -- the
		 * negative path is itself a reachable kernel code surface
		 * and shouldn't go entirely uncovered.
		 */
		if (ONE_IN(20))
			xflags |= ((unsigned long long) rnd_u32()) &
				  ~(unsigned long long) FILE_SETATTR_XFLAG_POOL_MASK;

		fa->fa_xflags = xflags;
	}

	rec->a3 = (unsigned long) fa;
	rec->a4 = buf.usize;

	/*
	 * a3 is ARG_ADDRESS, so the post-sanitise blanket address scrub
	 * would otherwise call avoid_shared_buffer_out() on it: that
	 * relocates the slot to a fresh pool page WITHOUT copying the
	 * libc-heap csfu bytes, so the kernel would read a zeroed page
	 * and the curated fa_xflags coverage would be silently lost.
	 * Move the input into the pool with the bytes intact; the
	 * blanket pass then no-ops on this slot.
	 */
	avoid_shared_buffer_inout(&rec->a3, buf.usize);

	/*
	 * Stash the canonical fa pointer in rec->post_state so the .cleanup
	 * hook can release it unconditionally -- .cleanup runs on every
	 * dispatch outcome, including paths that skip .post (retfd_rejected
	 * / rzs_rejected gates in handle_syscall_ret()).  post_state is
	 * private to the post / cleanup pair and less stomp-prone than
	 * rec->a3, which the syscall-arg ABI exposes to sibling
	 * value-result writes.  The kernel only reads fa synchronously
	 * during the syscall (no async lifetime past return), so a
	 * deterministic post-dispatch free in .cleanup replaces the
	 * pre-dispatch deferred_free_enqueue_or_leak() that owned the
	 * lifecycle before.
	 */
	rec->post_state = (unsigned long) fa;

	/*
	 * Bias at_flags (rec->a5) toward the kernel's allowlist:
	 *
	 *   if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
	 *           return -EINVAL;
	 *
	 * handle_arg_list ORs in shift_flag_bit() / CMP-hint bits for
	 * adjacent-bit probing on ~3/16 of calls; any bit outside the
	 * two-flag allowlist bounces the call straight back with -EINVAL
	 * before filename_lookup() and vfs_fileattr_set() ever run.  Mask
	 * the noise off ~7/8 of the time so the call reaches the real
	 * setattr path; ~1/8 leaves the OR'd noise intact so the reject
	 * path stays covered.  The mask only trims foreign bits -- the
	 * underlying ARG_LIST pick across {0, AT_SYMLINK_NOFOLLOW,
	 * AT_EMPTY_PATH, both} is preserved.  Mirrors the at_flags bias
	 * in the sibling file_getattr sanitiser.
	 */
	if (!ONE_IN(8))
		rec->a5 &= (unsigned long)
			   (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);

	/*
	 * dfd (a1): ARG_FD draws from the full fd pool (regular files,
	 * pipes, sockets, ...).  When pathname is relative the kernel
	 * does a dir-relative lookup against dfd and a non-directory fd
	 * is rejected with -ENOTDIR before any vfs_fileattr_set() work.
	 * Pin to AT_FDCWD on 1/3 of draws so the relative-path fraction
	 * lands on a usable base while leaving the random-fd path well
	 * exercised for the dfd-only (AT_EMPTY_PATH + NULL pathname)
	 * shape.
	 */
	if (ONE_IN(3))
		rec->a1 = (unsigned long)(long) AT_FDCWD;
}

static void cleanup_file_setattr(struct syscallrecord *rec)
{
	rec->a3 = 0;
	cleanup_release_post_state(rec);
}

struct syscallentry syscall_file_setattr = {
	.name = "file_setattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "ufattr", [3] = "usize", [4] = "at_flags" },
	.arg_params[4].list = ARGLIST(file_setattr_at_flags),
	.sanitise = sanitise_file_setattr,
	.cleanup = cleanup_file_setattr,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
