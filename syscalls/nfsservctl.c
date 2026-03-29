/*
 * SYSCALL_DEFINE3(nfsservctl, int, cmd, struct nfsctl_arg __user *, arg, void __user *, res
 */
#include "sanitise.h"

struct syscallentry syscall_nfsservctl = {
	.name = "nfsservctl",
	.num_args = 3,
	.argtype = { [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "cmd", [1] = "arg", [2] = "res" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
