/*
 * SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
	 const void __user *,value, size_t, size, int, flags)
 */

#include "rnd.h"
#include "sanitise.h"
#include "testfile.h"
#include "xattr.h"

static void sanitise_fsetxattr(struct syscallrecord *rec)
{
	int fd;

	xattr_set_value((const char *) rec->a2, &rec->a3, &rec->a4);
	avoid_shared_buffer_inout(&rec->a3, rec->a4);
	xattr_pick_set_flags(&rec->a5);

	/*
	 * ARG_FD plumbed a random fd into rec->a1, but on most draws it
	 * is the wrong kind of object for an xattr op (socket, pipe,
	 * eventfd, mq, ...) and vfs_setxattr returns EOPNOTSUPP at the
	 * front of the call before ever reaching the per-fs handler
	 * dispatch or the simple_xattr_add fast path the per-inode
	 * i_xattrs rwsem guards.  Cold-syscall shape ("high calls, low
	 * edges") the wall-lever shadow gate keeps re-flagging.
	 *
	 * Half the draws repoint at a real testfile fd so the
	 * trinity-dispatched fsetxattr lands inside the real per-inode
	 * set path -- this is the writer the get / list / remove
	 * planters cooperate with, so the plant itself happens via the
	 * dispatched call, not from inside sanitise.  The other half
	 * preserves the slot exactly as the generic draw left it, to
	 * keep the namespace-reject / EOPNOTSUPP arms warm.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	fd = get_rand_testfile_fd();
	if (fd >= 0)
		rec->a1 = (unsigned long) fd;
}

struct syscallentry syscall_fsetxattr = {
	.name = "fsetxattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_XATTR_NAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "name", [2] = "value", [3] = "size", [4] = "flags" },
	.arg_params[4].list = ARGLIST(xattr_set_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_XATTR,
	.sanitise = sanitise_fsetxattr,
};
