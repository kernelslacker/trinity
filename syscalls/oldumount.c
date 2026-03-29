/*
 * SYSCALL_DEFINE1(oldumount, char __user *, name)
 */
#include "sanitise.h"

struct syscallentry syscall_oldumount = {
	.name = "oldumount",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "name" },
	.group = GROUP_VFS,
};
