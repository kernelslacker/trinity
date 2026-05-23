/*
 * SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_fremovexattr(struct syscallrecord *rec)
{
	sanitise_xattr_name_arg_pooled(rec, 2);
}

struct syscallentry syscall_fremovexattr = {
	.name = "fremovexattr",
	.num_args = 2,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd", [1] = "name" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fremovexattr,
};
