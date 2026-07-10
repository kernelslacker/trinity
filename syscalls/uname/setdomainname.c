/*
 * SYSCALL_DEFINE2(setdomainname, char __user *, name, int, len)
 */
#include "sanitise.h"

struct syscallentry syscall_setdomainname = {
	.name = "setdomainname",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LEN },
	.argname = { [0] = "name", [1] = "len" },
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT,
};
