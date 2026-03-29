/*
 * SYSCALL_DEFINE2(fremovexattr, int, fd, const char __user *, name)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_fremovexattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
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
