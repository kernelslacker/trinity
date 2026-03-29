/*
 *
 * SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
 */
#include "sanitise.h"

struct syscallentry syscall_newuname = {
	.name = "newuname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.group = GROUP_PROCESS,
};
