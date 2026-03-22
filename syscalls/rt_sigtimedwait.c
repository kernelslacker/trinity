/*
 * SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
	 siginfo_t __user *, uinfo, const struct timespec __user *, uts,
	 size_t, sigsetsize)
 */
#include "sanitise.h"

struct syscallentry syscall_rt_sigtimedwait = {
	.name = "rt_sigtimedwait",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.arg1name = "uthese",
	.arg1type = ARG_ADDRESS,
	.arg2name = "uinfo",
	.arg2type = ARG_ADDRESS,
	.arg3name = "uts",
	.arg3type = ARG_ADDRESS,
	.arg4name = "sigsetsize",
	.arg4type = ARG_LEN,
	.flags = NEED_ALARM,
};
