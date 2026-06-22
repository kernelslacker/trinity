/*
 * SYSCALL_DEFINE4(removexattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name)
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/xattr.h>
#include "pathnames.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "xattr.h"
#include "compat.h"

/*
 * Curated name we plant ahead of the trinity-dispatched removexattrat.
 * Matches planted_xattr_name in lremovexattr / fremovexattr / getxattrat
 * so a single round of testfile xattrs is shared across the whole
 * xattr-family precondition surface.  user.* requires no privilege, is
 * supported on every Linux fs that carries xattrs, and lives in the
 * curated pool the ARG_XATTR_NAME draw already favours -- so the plant
 * overlaps with the existing name distribution instead of introducing a
 * fresh namespace the kernel rejects up front.
 */
static const char planted_xattr_name[] = "user.trinity_plant";

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the xattr-family
 * (getxattrat, lremovexattr, fremovexattr) touches; cross-process
 * contention concentrates on the same per-inode i_xattrs rwsem.
 */
#define NR_TESTFILES 4

static void sanitise_removexattrat(struct syscallrecord *rec)
{
	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a2 and
	 * ARG_XATTR_NAME filled rec->a4 with a namespace-shaped name
	 * from the curated pool, but the random path is most often not
	 * a real file (ENOENT) or, even when it does land on a real
	 * file, the drawn name is not currently set on that inode --
	 * path_removexattrat -> vfs_removexattr returns ENOTSUP / ENODATA
	 * at the front of the call before ever touching the per-fs
	 * handler dispatch or the simple_xattr_remove fast path that the
	 * per-inode i_xattrs rwsem guards.  Same "high calls, low edges"
	 * cold-syscall shape that lremovexattr / fremovexattr were in
	 * before their testfile-plant fixes.
	 *
	 * Half the draws now repoint pathname (a2) at one of the
	 * trinity-testfile<N> absolute paths and overwrite the name (a4)
	 * buffer in place with the curated user.* token, then plant the
	 * value on disk via setxattr() so the subsequent removexattrat
	 * lands inside the real per-inode remove path.  An absolute
	 * pathname makes dfd irrelevant -- the kernel ignores rec->a1
	 * when pathname is absolute -- so this composes cleanly with the
	 * AT_FDCWD-pin / random-fd dfd logic and the at_flags sanitiser
	 * below; the planted testfiles are regular files so
	 * AT_SYMLINK_NOFOLLOW is a no-op on them, and the absolute
	 * non-empty path makes AT_EMPTY_PATH irrelevant too.
	 *
	 * The other half preserves rec->a2 / rec->a4 exactly as the
	 * generic draw left them so the namespace-reject / ENODATA arms
	 * stay exercised.
	 *
	 * Slow-path note: the setxattr() in sanitise is one real syscall.
	 * syscalls/removexattrat.c is outside the sanitiser-slow-path
	 * check's FILES scope, so this is within budget for the
	 * precondition payoff.
	 */
	if (rnd_modulo_u32(2) == 0) {
		char *path = (char *) rec->a2;
		char *name = (char *) rec->a4;

		if (path != NULL && name != NULL) {
			/*
			 * Overwrite the ARG_PATHNAME / ARG_XATTR_NAME
			 * buffers in place.  generate_pathname() zmallocs
			 * MAX_PATH_LEN (4096) bytes; the xattr name buffer
			 * is XATTR_NAME_BUFSZ (256) bytes; both comfortably
			 * fit the planted values.
			 */
			snprintf(path, MAX_PATH_LEN,
				 "%s/trinity-testfile%u",
				 trinity_tmpdir_abs(),
				 1 + rnd_modulo_u32(NR_TESTFILES));
			memcpy(name, planted_xattr_name,
			       sizeof(planted_xattr_name));
			/*
			 * Plant a small opaque value.  Failure (ENOSPC on
			 * a full xattr list, EOPNOTSUPP on a fs that bailed
			 * out of the user.* leg, ENOENT if the testfile
			 * slot was never opened, ...) is non-fatal: an
			 * earlier draw on the same inode may still hold a
			 * stale user.trinity_plant from a prior round, so
			 * the trinity-dispatched removexattrat below may
			 * still land on the real remove path.
			 */
			(void) setxattr(path, name, "trin", 4, 0);
		}
	}

	/*
	 * at_flags (a3): handle_arg_list's 1/8 shift_flag_bit and 1/16
	 * cmp-hint paths regularly OR in bits outside the kernel-accepted
	 * (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) mask, and path_removexattrat
	 * rejects those with -EINVAL before any xattr-remove work runs.
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

struct syscallentry syscall_removexattrat = {
	.name = "removexattrat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_XATTR_NAME },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name" },
	.arg_params[2].list = ARGLIST(xattrat_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_removexattrat,
};
