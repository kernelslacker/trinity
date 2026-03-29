/*
 * SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
 */
#include "sanitise.h"

struct syscallentry syscall_sysinfo = {
	.name = "sysinfo",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "info" },
	.group = GROUP_PROCESS,
};
