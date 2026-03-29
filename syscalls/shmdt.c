/*
 * SYSCALL_DEFINE1(shmdt, char __user *, shmaddr)
 */
#include "sanitise.h"

struct syscallentry syscall_shmdt = {
	.name = "shmdt",
	.group = GROUP_IPC,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "shmaddr" },
};
