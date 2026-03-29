/*
 * SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd, void __user *, arg)
 */
#include "sanitise.h"

struct syscallentry syscall_reboot = {
	.name = "reboot",
	.num_args = 4,
	.argtype = { [3] = ARG_ADDRESS },
	.argname = { [0] = "magic1", [1] = "magic2", [2] = "cmd", [3] = "arg" },
	.group = GROUP_PROCESS,
};
