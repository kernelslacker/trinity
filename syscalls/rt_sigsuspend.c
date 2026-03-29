/*
 * SYSCALL_DEFINE2(rt_sigsuspend, sigset_t __user *, unewset, size_t, sigsetsize)
 */
#include "sanitise.h"

struct syscallentry syscall_rt_sigsuspend = {
	.name = "rt_sigsuspend",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "unewset", [1] = "sigsetsize" },
	.flags = AVOID_SYSCALL,
};
