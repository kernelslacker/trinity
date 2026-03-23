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
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
}

struct syscallentry syscall_fsetxattr = {
	.name = "fsetxattr",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "name",
	.arg3name = "value",
	.arg3type = ARG_ADDRESS,
	.arg4name = "size",
	.arg4type = ARG_LEN,
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(fsetxattr_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fsetxattr,
};
