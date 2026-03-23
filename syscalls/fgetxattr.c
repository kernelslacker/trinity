/*
 * SYSCALL_DEFINE4(fgetxattr, int, fd, const char __user *, name,
	 void __user *, value, size_t, size)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_fgetxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
}

struct syscallentry syscall_fgetxattr = {
	.name = "fgetxattr",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "name",
	.arg3name = "value",
	.arg3type = ARG_ADDRESS,
	.arg4name = "size",
	.arg4type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_fgetxattr,
};
