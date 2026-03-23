/*
 * SYSCALL_DEFINE2(removexattr, const char __user *, pathname, const char __user *, name)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_removexattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
}

struct syscallentry syscall_removexattr = {
	.name = "removexattr",
	.num_args = 2,
	.arg1name = "pathname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "name",
	.group = GROUP_VFS,
	.sanitise = sanitise_removexattr,
};
