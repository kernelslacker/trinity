/*
 * SYSCALL_DEFINE6(setxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		const struct xattr_args __user *, uargs, size_t, usize)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "xattr.h"
#include "compat.h"

static unsigned long setxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

static void sanitise_setxattrat(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_address(256);
	gen_xattr_name(name, 256);
	rec->a4 = (unsigned long) name;
}

struct syscallentry syscall_setxattrat = {
	.name = "setxattrat",
	.num_args = 6,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "at_flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(setxattrat_at_flags),
	.arg4name = "name",
	.arg5name = "uargs",
	.arg5type = ARG_ADDRESS,
	.arg6name = "usize",
	.arg6type = ARG_LEN,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
	.sanitise = sanitise_setxattrat,
};
