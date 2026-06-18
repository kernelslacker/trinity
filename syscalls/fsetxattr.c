/*
 * SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
	 const void __user *,value, size_t, size, int, flags)
 */

#include "sanitise.h"
#include "xattr.h"

static void sanitise_fsetxattr(struct syscallrecord *rec)
{
	xattr_set_value((const char *) rec->a2, &rec->a3, &rec->a4);
	xattr_pick_set_flags(&rec->a5);
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
