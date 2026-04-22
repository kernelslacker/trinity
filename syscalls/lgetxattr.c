/*
 * SYSCALL_DEFINE4(lgetxattr, const char __user *, pathname,
	 const char __user *, name, void __user *, value, size_t, size)
 */
#include "sanitise.h"
#include "xattr.h"

static void sanitise_lgetxattr(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a2 = (unsigned long) name;
	avoid_shared_buffer(&rec->a3, rec->a4);
}

struct syscallentry syscall_lgetxattr = {
	.name = "lgetxattr",
	.num_args = 4,
	.argtype = { [0] = ARG_PATHNAME, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "pathname", [1] = "name", [2] = "value", [3] = "size" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_lgetxattr,
};
