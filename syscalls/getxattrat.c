/*
 * SYSCALL_DEFINE6(getxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		struct xattr_args __user *, uargs, size_t, usize)
 */
#include <fcntl.h>
#include "arch.h"
#include "sanitise.h"
#include "xattr.h"
#include "compat.h"
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif

static unsigned long getxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

static void sanitise_getxattrat(struct syscallrecord *rec)
{
	char *name = (char *) get_writable_struct(256);

	if (!name)
		return;
	gen_xattr_name(name, 256);
	rec->a4 = (unsigned long) name;

#ifdef USE_XATTR_ARGS
	{
		static const unsigned int flag_choices[] = { 0, XATTR_CREATE, XATTR_REPLACE };
		struct xattr_args *args;

		args = (struct xattr_args *) get_writable_struct(sizeof(*args));
		if (!args)
			return;
		args->value = (unsigned long) get_writable_struct(256);
		if (!args->value)
			return;
		args->size = 256;
		args->flags = flag_choices[rand() % 3];
		rec->a5 = (unsigned long) args;
		rec->a6 = sizeof(*args);
	}
#else
	avoid_shared_buffer(&rec->a5, page_size);
#endif
}

struct syscallentry syscall_getxattrat = {
	.name = "getxattrat",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name", [4] = "uargs", [5] = "usize" },
	.arg_params[2].list = ARGLIST(getxattrat_at_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_getxattrat,
};
