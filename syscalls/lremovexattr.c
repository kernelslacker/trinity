/*
 * SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname, const char __user *, name)
 */
#include <sys/xattr.h>
#include <stdio.h>
#include <string.h>
#include "pathnames.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "xattr.h"

/*
 * Curated name we plant ahead of the trinity-dispatched lremovexattr.
 * Path-based mirror of the planted_xattr_name fremovexattr uses on the
 * testfile-fd repoint: user.* requires no privilege, is supported on
 * every Linux fs that carries xattrs, and lives in the curated pool the
 * ARG_XATTR_NAME draw already favours -- so the plant overlaps with the
 * existing name distribution instead of introducing a fresh namespace
 * the kernel rejects up front.
 */
static const char planted_xattr_name[] = "user.trinity_plant";

/*
 * Mirrors the MAX_TESTFILES bound in fds/testfiles.c so we land inside
 * the same trinity-testfile<N> inodes the rest of the fuzzer
 * (xattr-thrash, flock-thrash, fremovexattr) touches; cross-process
 * contention concentrates on the same per-inode i_xattrs rwsem.
 */
#define NR_TESTFILES 4

static void sanitise_lremovexattr(struct syscallrecord *rec)
{
	char *path;
	char *name;

	/*
	 * ARG_PATHNAME plumbed a random pathname into rec->a1 and
	 * ARG_XATTR_NAME filled rec->a2 with a namespace-shaped name
	 * from the curated pool.  But the random path is most often
	 * either not a real file at all (ENOENT) or, even when it
	 * does land on a real file, the drawn name is not currently
	 * set -- vfs_removexattr returns ENOTSUP / ENODATA at the
	 * front of the call before ever touching the per-fs handler
	 * dispatch or the simple_xattr_remove fast path that the
	 * per-inode i_xattrs rwsem guards.  Same "high calls, low
	 * edges" cold-syscall shape that fremovexattr was in before
	 * the f0d5ab520c00 testfile-fd repoint.
	 *
	 * Half the draws now repoint at one of the trinity-testfile<N>
	 * absolute paths and plant a known user.* xattr there via
	 * setxattr() so the subsequent lremovexattr lands inside the
	 * real per-inode remove path.  The other half preserves the
	 * slot exactly as the generic draw left it, so the
	 * namespace-reject / ENODATA arms stay exercised.
	 *
	 * Slow-path note: setxattr() inside sanitise is one real
	 * syscall.  syscalls/lremovexattr.c is outside the
	 * sanitiser-slow-path check's FILES scope, so this is within
	 * budget for the precondition payoff.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	name = (char *) rec->a2;
	if (name == NULL)
		return;

	/*
	 * The ARG_XATTR_NAME buffer at rec->a2 is XATTR_NAME_BUFSZ (256)
	 * bytes and is overwritten in place; it comfortably fits the
	 * planted value.  Plant and trinity-dispatched lremovexattr see
	 * the same byte sequences.
	 */
	path = get_testfile_path();
	if (path == NULL)
		return;

	rec->a1 = (unsigned long) path;
	memcpy(name, planted_xattr_name, sizeof(planted_xattr_name));

	/*
	 * Plant a small opaque value.  Failure (ENOSPC on a full xattr
	 * list, EOPNOTSUPP on a fs that bailed out of the user.* leg,
	 * ENOENT if the testfile was never opened, ...) is non-fatal:
	 * an earlier draw on the same inode may still hold a stale
	 * user.trinity_plant from a prior round, so the trinity-
	 * dispatched lremovexattr below may still land on the real
	 * remove path.
	 */
	(void) setxattr(path, name, "trin", 4, 0);
}

struct syscallentry syscall_lremovexattr = {
	.name = "lremovexattr",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_XATTR_NAME },
	.argname = { [0] = "pathname", [1] = "name" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_lremovexattr,
};
