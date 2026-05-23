/*
 * SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname, const char __user *, name)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_lremovexattr(struct syscallrecord *rec)
{
	sanitise_xattr_name_arg_pooled(rec, 2);
}

struct syscallentry syscall_lremovexattr = {
	.name = "lremovexattr",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "pathname", [1] = "name" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_lremovexattr,
};
