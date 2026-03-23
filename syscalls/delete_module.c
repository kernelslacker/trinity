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
	.arg1name = "name_user",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(delete_module_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
};
