/*
 * SYSCALL_DEFINE4(rt_tgsigqueueinfo, pid_t, tgid, pid_t, pid, int, sig,
	 siginfo_t __user *, uinfo)
 */
#include <signal.h>
#include "sanitise.h"

struct syscallentry syscall_rt_tgsigqueueinfo = {
	.name = "rt_tgsigqueueinfo",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.arg1name = "tgid",
	.arg1type = ARG_PID,
	.arg2name = "pid",
	.arg2type = ARG_PID,
	.arg3name = "sig",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = _NSIG,
	.arg4name = "uinfo",
	.arg4type = ARG_ADDRESS,
};
