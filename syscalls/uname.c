/*
 * SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
 */
#include "sanitise.h"

struct syscallentry syscall_uname = {
	.name = "uname",
	.num_args = 1,
	.arg1name = "name",
	.arg1type = ARG_ADDRESS,
};
