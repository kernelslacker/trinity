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
#include "compat.h"
#include "utils.h"

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
	FS_XFLAG_HASATTR,
};

#define FILE_SETATTR_XFLAG_POOL_MASK					\
	(FS_XFLAG_REALTIME | FS_XFLAG_PREALLOC | FS_XFLAG_IMMUTABLE |	\
	 FS_XFLAG_APPEND | FS_XFLAG_SYNC | FS_XFLAG_NOATIME |		\
	 FS_XFLAG_NODUMP | FS_XFLAG_RTINHERIT | FS_XFLAG_PROJINHERIT |	\
	 FS_XFLAG_NOSYMLINKS | FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT |\
	 FS_XFLAG_NODEFRAG | FS_XFLAG_FILESTREAM | FS_XFLAG_DAX |	\
	 FS_XFLAG_COWEXTSIZE | FS_XFLAG_HASATTR)

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
	 * Hand the csfu buffer to the deferred-free queue up front --
	 * the zmalloc_tracked() allocation has no other release path.
	 */
	deferred_free_enqueue(fa);

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
}

struct syscallentry syscall_file_setattr = {
	.name = "file_setattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "ufattr", [3] = "usize", [4] = "at_flags" },
	.arg_params[4].list = ARGLIST(file_setattr_at_flags),
	.sanitise = sanitise_file_setattr,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
