/*
 * SYSCALL_DEFINE2(delete_module, const char __user *, name_user, unsigned int, flags
 *
 * On success, zero is returned.
 * On error, -1 is returned and errno is set appropriately.
 */
#include <fcntl.h>
#include "sanitise.h"

static unsigned long delete_module_flags[] = {
	O_NONBLOCK, O_TRUNC,
};

struct syscallentry syscall_delete_module = {
	.name = "delete_module",
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LIST },
	.argname = { [0] = "name_user", [1] = "flags" },
	.arg2list = ARGLIST(delete_module_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
};
