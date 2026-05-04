/*
 * SYSCALL_DEFINE5(fsetxattr, int, fd, const char __user *, name,
	 const void __user *,value, size_t, size, int, flags)
 */

#include <linux/xattr.h>
#include "sanitise.h"
#include "xattr.h"

static unsigned long fsetxattr_flags[] = {
	XATTR_CREATE, XATTR_REPLACE,
};

static void sanitise_fsetxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
}

struct syscallentry syscall_fsetxattr = {
	.name = "fsetxattr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "name", [2] = "value", [3] = "size", [4] = "flags" },
	.arg_params[4].list = ARGLIST(fsetxattr_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fsetxattr,
};
