/*
 * SYSCALL_DEFINE6(setxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		const struct xattr_args __user *, uargs, size_t, usize)
 */
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include "arch.h"
#include "csfu.h"
#include "deferred-free.h"
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"
#include "xattr.h"
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#include "kernel/fcntl.h"
#endif

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so the pinned
 * arm lands inside the same trinity-testfile<N> inodes the rest of
 * the fuzzer (xattr-thrash, flock-thrash, fremovexattr, lremovexattr,
 * llistxattr) touches; cross-process contention concentrates on the
 * same per-inode i_xattrs rwsem.
 */
#define NR_TESTFILES 4

static unsigned long setxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

#ifdef USE_XATTR_ARGS
/*
 * Single-version ABI today: struct xattr_args has only one published
 * layout, so there is no pre-ksize ABI floor to seed the UNDERSIZE
 * bucket from.  The current ksize is kept in known_sizes[] so the
 * table stays self-documenting and remains correct if the kernel
 * ever grows a VER1.
 */
static const size_t setxattrat_known_sizes[] = {
	sizeof(struct xattr_args),
};

static const struct csfu_desc desc_setxattrat = {
	.name = "xattr_args",
	.ksize = sizeof(struct xattr_args),
	.known_sizes = setxattrat_known_sizes,
	.n_known_sizes = ARRAY_SIZE(setxattrat_known_sizes),
};
#endif

#ifdef USE_XATTR_ARGS
static bool sanitise_setxattrat_build_args(struct syscallrecord *rec)
{
	static const unsigned int flag_choices[] = { 0, XATTR_CREATE, XATTR_REPLACE };
	struct csfu_buf buf = build_csfu_struct(&desc_setxattrat);
	struct xattr_args *args = buf.ptr;

	if (!args)
		return false;

	/*
	 * Stash the csfu buffer in rec->post_state up front so the
	 * unconditional .cleanup hook frees it even on the value-buffer
	 * allocation-failure return below.  setxattrat has no .post handler,
	 * so this was the only release point; post_state is private to the
	 * cleanup path and less stomp-prone than rec->a5.
	 */
	rec->post_state = (unsigned long) args;

	/*
	 * Non-EXACT buckets get rejected on size by the validator
	 * before the kernel reads any body field, so populating
	 * args->value / size / flags (and allocating the value
	 * sub-buffer they reference) is wasted work.  The
	 * zmalloc_tracked() buffer is already zeroed where the
	 * kernel cares to look.
	 */
	if (buf.bucket == CSFU_BUCKET_EXACT) {
		__u32 chosen;

		switch (rnd_modulo_u32(9)) {
		case 0:  chosen = 0;                  break;
		case 1:  chosen = 1;                  break;
		case 2:  chosen = 32;                 break;
		case 3:  chosen = 256;                break;
		case 4:  chosen = page_size;          break;
		case 5:  chosen = page_size + 1;      break;
		case 6:  chosen = 65536;              break;
		case 7:  chosen = 65537;              break;
		default: chosen = rnd_modulo_u32(1u << 20); break;
		}

		if (chosen == 0) {
			args->value = 0;
		} else {
			void *value = get_writable_struct(chosen);
			if (!value) {
				/*
				 * Publish safe defaults so the syscall
				 * doesn't run with stale rec->a5/rec->a6
				 * from a prior iteration.  args/buf both
				 * stack-resident — zeroing the published
				 * slots is enough; the kernel will see
				 * NULL uargs and reject cleanly.
				 */
				rec->a5 = 0;
				rec->a6 = 0;
				return false;
			}
			args->value = (unsigned long) value;
		}
		args->size = chosen;
		args->flags = flag_choices[rnd_modulo_u32(3)];
	}

	rec->a5 = (unsigned long) args;
	avoid_shared_buffer_inout(&rec->a5, buf.usize);
	rec->a6 = buf.usize;
	return true;
}
#endif

static void sanitise_setxattrat_scrub_flags(struct syscallrecord *rec)
{
	/*
	 * at_flags (a3): handle_arg_list's 1/8 shift_flag_bit and 1/16
	 * cmp-hint paths regularly OR in bits outside the kernel-accepted
	 * (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) mask, and path_setxattrat
	 * rejects those with -EINVAL before any xattr-set work runs.
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
}

/*
 * pathname (a2): ARG_PATHNAME plumbed a random pathname into the
 * slot, but the random path is most often not a real file at all
 * (ENOENT before any vfs_setxattr work) or, even when it lands on
 * a real file, path_setxattrat bounces it before the per-fs xattr
 * handler dispatch and the per-inode i_xattrs rwsem the set would
 * have grabbed.  Same "high calls, low edges" cold-syscall shape
 * the rest of the xattr family had before their testfile
 * precondition repoints (fremovexattr / lremovexattr / llistxattr).
 *
 * Half the draws now repoint at one of the trinity-testfile<N>
 * absolute paths so the set lands on a real per-inode xattr list
 * and exercises the per-fs handler dispatch.  The other half
 * preserves the slot exactly as ARG_PATHNAME left it so the
 * ENOENT / random-path reject arms stay warm.  The absolute path
 * makes the dfd choice irrelevant for the pinned arm, so this
 * composes cleanly with the AT_FDCWD pin above.
 *
 * setxattrat is itself the set, so no separate plant is needed --
 * the syscall populates the per-inode xattr list directly.  This
 * is path-pin only, no sanitiser-slow-path setxattr() call.
 */
static void sanitise_setxattrat_repoint_pathname(struct syscallrecord *rec)
{
	if (rnd_modulo_u32(2) == 0) {
		char *path = get_testfile_path();

		if (path != NULL)
			rec->a2 = (unsigned long) path;
	}
}

static void sanitise_setxattrat(struct syscallrecord *rec)
{
#ifdef USE_XATTR_ARGS
	if (!sanitise_setxattrat_build_args(rec))
		return;
#endif

	sanitise_setxattrat_scrub_flags(rec);
	sanitise_setxattrat_repoint_pathname(rec);
}

#ifdef USE_XATTR_ARGS
static void cleanup_setxattrat(struct syscallrecord *rec)
{
	cleanup_release_post_state(rec);
}
#endif

struct syscallentry syscall_setxattrat = {
	.name = "setxattrat",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_XATTR_NAME, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name", [4] = "uargs", [5] = "usize" },
	.arg_params[2].list = ARGLIST(setxattrat_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_setxattrat,
#ifdef USE_XATTR_ARGS
	.cleanup = cleanup_setxattrat,
#endif
};
