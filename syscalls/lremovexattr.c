/*
 * SYSCALL_DEFINE2(lremovexattr, const char __user *, pathname, const char __user *, name)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_lremovexattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
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
