/*
 * SYSCALL_DEFINE6(getxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, const char __user *, name,
 *		struct xattr_args __user *, uargs, size_t, usize)
 */
#include "arch.h"
#include "rnd.h"
#include "sanitise.h"
#include "xattr.h"
#include "compat.h"
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif

static void sanitise_getxattrat(struct syscallrecord *rec)
{
	if (!sanitise_xattr_name_arg(rec, 4))
		return;

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
		args->flags = flag_choices[rnd_modulo_u32(3)];
		rec->a5 = (unsigned long) args;
		rec->a6 = sizeof(*args);
	}
#else
	avoid_shared_buffer_out(&rec->a5, page_size);
#endif
}

struct syscallentry syscall_getxattrat = {
	.name = "getxattrat",
	.num_args = 6,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [4] = ARG_ADDRESS, [5] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "name", [4] = "uargs", [5] = "usize" },
	.arg_params[2].list = ARGLIST(xattrat_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_getxattrat,
};
