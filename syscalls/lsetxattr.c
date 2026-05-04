/*
 * SYSCALL_DEFINE5(lsetxattr, const char __user *, pathname,
	 const char __user *, name, const void __user *, value,
	 size_t, size, int, flags)
 */

#include <linux/xattr.h>
#include "sanitise.h"
#include "xattr.h"

static unsigned long lsetxattr_flags[] = {
	XATTR_CREATE, XATTR_REPLACE,
};

static void sanitise_lsetxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
}

struct syscallentry syscall_lsetxattr = {
	.name = "lsetxattr",
	.num_args = 5,
	.argtype = { [0] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_LIST },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size", [4] = "flags" },
	.arg_params[4].list = ARGLIST(lsetxattr_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_lsetxattr,
};
