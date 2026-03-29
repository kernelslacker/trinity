/*
 * SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, set, size_t, sigsetsize)
 */
#include "sanitise.h"

struct syscallentry syscall_rt_sigpending = {
	.name = "rt_sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "set", [1] = "sigsetsize" },
};
