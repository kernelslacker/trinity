/*
 * SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf)
 */
#include "sanitise.h"

struct syscallentry syscall_ustat = {
	.name = "ustat",
	.num_args = 2,
	.argtype = { [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "dev", [1] = "ubuf" },
	.group = GROUP_VFS,
};
