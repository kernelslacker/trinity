/*
 * SYSCALL_DEFINE2(rt_sigsuspend, sigset_t __user *, unewset, size_t, sigsetsize)
 */
#include "sanitise.h"

struct syscallentry syscall_rt_sigsuspend = {
	.name = "rt_sigsuspend",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.arg1name = "unewset",
	.arg1type = ARG_ADDRESS,
	.arg2name = "sigsetsize",
	.arg2type = ARG_LEN,
	.flags = AVOID_SYSCALL,
};
