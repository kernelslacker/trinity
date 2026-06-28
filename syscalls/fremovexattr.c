/*
 * SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
 */
#include <sys/xattr.h>
#include <string.h>
#include "rnd.h"
#include "sanitise.h"
#include "testfile.h"
#include "xattr.h"

/*
 * Curated name we plant ahead of the trinity-dispatched fremovexattr.
 * user.* requires no privilege, is supported on every Linux fs that
 * carries xattrs at all, and lives in the curated pool the
 * ARG_XATTR_NAME draw already favours -- so the plant overlaps with
 * the existing name distribution instead of introducing a fresh
 * namespace the kernel rejects up front.
 */
static const char planted_xattr_name[] = "user.trinity_plant";

static void sanitise_fremovexattr(struct syscallrecord *rec)
{
	int fd;
	char *name;

	/*
	 * ARG_FD plumbed a random fd into rec->a1 and ARG_XATTR_NAME
	 * filled rec->a2 with a namespace-shaped name from the curated
	 * pool.  But the fd is most often the wrong kind of object for
	 * an xattr op (socket, pipe, eventfd, mq, ...) or, even when it
	 * lands on a real file, the drawn name is not currently set --
	 * vfs_removexattr returns ENOTSUP / ENODATA at the front of the
	 * call before ever touching the per-fs handler dispatch or the
	 * simple_xattr_remove fast path that the per-inode i_xattrs
	 * rwsem guards.  "high calls, low edges" cold-syscall shape that
	 * the wall-lever shadow gate keeps re-flagging.
	 *
	 * Half the draws now repoint at a testfile fd and plant a known
	 * user.* xattr there via fsetxattr() so the subsequent
	 * fremovexattr lands inside the real per-inode remove path.  The
	 * other half preserves the slot exactly as the generic draw left
	 * it, so the namespace-reject / ENODATA arms stay exercised.
	 *
	 * Slow-path note: fsetxattr() inside sanitise is a real syscall.
	 * syscalls/fremovexattr.c is outside the sanitiser-slow-path
	 * check's FILES scope, so this is within budget for the
	 * precondition payoff (zero per-inode-remove edges -> real
	 * remove edges).
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	fd = get_rand_testfile_fd();
	if (fd < 0)
		return;

	name = (char *) rec->a2;
	if (name == NULL)
		return;

	/* Overwrite the ARG_XATTR_NAME-allocated buffer in place so the
	 * plant we make from sanitise and the trinity-dispatched
	 * fremovexattr that follows see the same byte sequence.  Buffer
	 * is XATTR_NAME_BUFSZ (256); planted_xattr_name fits with room
	 * to spare. */
	memcpy(name, planted_xattr_name, sizeof(planted_xattr_name));

	/* Plant a small opaque value.  Failure here (ENOSPC on full
	 * xattr list, EOPNOTSUPP on an fs that bailed out of the user.*
	 * leg, ...) is non-fatal: an earlier draw on the same fd may
	 * still hold a stale user.trinity_plant from a prior round, so
	 * fremovexattr below may still land on the real remove path. */
	(void) fsetxattr(fd, name, "trin", 4, 0);

	rec->a1 = (unsigned long) fd;
}

struct syscallentry syscall_fremovexattr = {
	.name = "fremovexattr",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_XATTR_NAME },
	.argname = { [0] = "fd", [1] = "name" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_fremovexattr,
};
