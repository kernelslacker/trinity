/*
 * SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname,
	 int, newdfd, const char __user *, newname, int, flags)
 */
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"

#ifndef AT_SYMLINK_FOLLOW
#define AT_SYMLINK_FOLLOW	0x400
#endif

/*
 * linkat(2) flag space is narrow: AT_SYMLINK_FOLLOW (resolve oldname
 * through trailing symlinks) and AT_EMPTY_PATH (oldname must be ""
 * and olddfd must reference the inode to link, requires
 * CAP_DAC_READ_SEARCH).  Random bit-fill almost never hits the
 * AT_EMPTY_PATH+empty-string shape, so build explicit buckets.
 */
static int pick_flags(void)
{
	switch (rnd_modulo_u32(20)) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
		/* default: no flags, no-follow link */
		return 0;
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
		return AT_SYMLINK_FOLLOW;
	case 13:
	case 14:
	case 15:
	case 16:
		return AT_EMPTY_PATH;
	case 17:
		return AT_EMPTY_PATH | AT_SYMLINK_FOLLOW;
	default:
		/* random garbage bits in the high half */
		return (int) (rnd_u32() & 0xffff0000);
	}
}

static void sanitise_linkat(struct syscallrecord *rec)
{
	int flags;

	flags = pick_flags();
	rec->a5 = (unsigned long) flags;

	/*
	 * olddfd bucket.  AT_FDCWD ~40% so the relative-path lookup
	 * dominates; otherwise leave whatever ARG_FD generated (which
	 * may be a real directory fd, a regular file fd, or AT_FDCWD
	 * via the existing one-in-100 path in this sanitiser's
	 * predecessor).  Small bucket of clearly-invalid sentinel fds
	 * keeps the EBADF reject warm.
	 */
	switch (rnd_modulo_u32(20)) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
		rec->a1 = (unsigned long)(long) AT_FDCWD;
		break;
	case 8:
		rec->a1 = (unsigned long)(long) -1;
		break;
	case 9:
		rec->a1 = (unsigned long) rnd_u32();
		break;
	default:
		/* keep ARG_FD value */
		break;
	}

	/* Same bucket for newdfd. */
	switch (rnd_modulo_u32(20)) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
		rec->a3 = (unsigned long)(long) AT_FDCWD;
		break;
	case 8:
		rec->a3 = (unsigned long)(long) -1;
		break;
	case 9:
		rec->a3 = (unsigned long) rnd_u32();
		break;
	default:
		break;
	}

	/*
	 * AT_EMPTY_PATH requires oldname to be the empty string and
	 * the link target is then re-resolved from olddfd's inode.
	 * The ARG_PATHNAME buffer is a fresh zmalloc(MAX_PATH_LEN) so
	 * writing a single NUL byte is safe and leaves the heap
	 * pointer intact for any post-handler free.  Without this the
	 * kernel rejects with -ENOENT before touching the empty-path
	 * code path.
	 */
	if ((flags & AT_EMPTY_PATH) && rec->a2 != 0)
		((char *) rec->a2)[0] = '\0';
}

struct syscallentry syscall_linkat = {
	.name = "linkat",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_FD, [3] = ARG_PATHNAME },
	.argname = { [0] = "olddfd", [1] = "oldname", [2] = "newdfd", [3] = "newname", [4] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_linkat,
};
