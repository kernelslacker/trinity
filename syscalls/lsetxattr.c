/*
 * SYSCALL_DEFINE5(lsetxattr, const char __user *, pathname,
	 const char __user *, name, const void __user *, value,
	 size_t, size, int, flags)
 */

#include "sanitise.h"
#include "xattr.h"

static void sanitise_lsetxattr(struct syscallrecord *rec)
{
	sanitise_xattr_name_arg(rec, 2);
}

struct syscallentry syscall_lsetxattr = {
	.name = "lsetxattr",
	.num_args = 5,
	.argtype = { [0] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size", [4] = "flags" },
	.arg_params[4].list = ARGLIST(xattr_set_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_lsetxattr,
};
