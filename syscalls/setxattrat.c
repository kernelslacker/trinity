/*
 * SYSCALL_DEFINE6(setxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		const struct xattr_args __user *, uargs, size_t, usize)
 */
#include <fcntl.h>
#include <linux/xattr.h>
#include "sanitise.h"
#include "xattr.h"
#include "compat.h"

static unsigned long setxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

static void sanitise_setxattrat(struct syscallrecord *rec)
{
	static const unsigned int flag_choices[] = { 0, XATTR_CREATE, XATTR_REPLACE };
	struct xattr_args *args;
	char *name = (char *) get_writable_address(256);

	gen_xattr_name(name, 256);
	rec->a4 = (unsigned long) name;

	args = (struct xattr_args *) get_writable_address(sizeof(*args));
	args->value = (unsigned long) get_writable_address(256);
	args->size = 256;
	args->flags = flag_choices[rand() % 3];
	rec->a5 = (unsigned long) args;
	rec->a6 = sizeof(*args);
}

struct syscallentry syscall_setxattrat = {
	.name = "setxattrat",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name", [4] = "uargs", [5] = "usize" },
	.arg_params[2].list = ARGLIST(setxattrat_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_setxattrat,
};
