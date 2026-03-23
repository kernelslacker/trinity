/*
 * SYSCALL_DEFINE4(getxattr, const char __user *, pathname,
	 const char __user *, name, void __user *, value, size_t, size)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_getxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
}

struct syscallentry syscall_getxattr = {
	.name = "getxattr",
	.num_args = 4,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "name",
	.arg3name = "value",
	.arg3type = ARG_ADDRESS,
	.arg4name = "size",
	.arg4type = ARG_LEN,
	.group = GROUP_VFS,
	.sanitise = sanitise_getxattr,
};
