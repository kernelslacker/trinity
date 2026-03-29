/*
 * SYSCALL_DEFINE1(uselib, const char __user *, library)
 */
#include "sanitise.h"

struct syscallentry syscall_uselib = {
	.name = "uselib",
	.num_args = 1,
	.argtype = { [0] = ARG_PATHNAME },
	.argname = { [0] = "library" },
	.group = GROUP_VFS,
};
