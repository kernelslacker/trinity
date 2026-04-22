/*
 * SYSCALL_DEFINE5(listxattrat, int, dfd, const char __user *, pathname,
 *		unsigned int, at_flags, char __user *, list, size_t, size)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long listxattrat_at_flags[] = {
	AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH,
};

static void sanitise_listxattrat(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a4, rec->a5);
}

struct syscallentry syscall_listxattrat = {
	.name = "listxattrat",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_ADDRESS, [4] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "pathname", [2] = "at_flags", [3] = "list", [4] = "size" },
	.arg_params[2].list = ARGLIST(listxattrat_at_flags),
	.sanitise = sanitise_listxattrat,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
