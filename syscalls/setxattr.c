/*
 * SYSCALL_DEFINE5(setxattr, const char __user *, pathname,
	 const char __user *, name, const void __user *, value,
	 size_t, size, int, flags)
 */

#include <linux/xattr.h>
#include "sanitise.h"
#include "xattr.h"

static unsigned long setxattr_flags[] = {
	XATTR_CREATE, XATTR_REPLACE,
};

static void sanitise_setxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
}

struct syscallentry syscall_setxattr = {
	.name = "setxattr",
	.num_args = 5,
	.argtype = { [0] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size", [4] = "flags" },
	.arg_params[4].list = ARGLIST(setxattr_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_setxattr,
};
