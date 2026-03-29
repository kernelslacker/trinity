/*
 * SYSCALL_DEFINE(lookup_dcookie)(u64 cookie64, char __user * buf, size_t len)
 */
#include "sanitise.h"

struct syscallentry syscall_lookup_dcookie = {
	.name = "lookup_dcookie",
	.num_args = 3,
	.argtype = { [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "cookie64", [1] = "buf", [2] = "len" },
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
