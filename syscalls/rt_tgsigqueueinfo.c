/*
 * SYSCALL_DEFINE4(rt_tgsigqueueinfo, pid_t, tgid, pid_t, pid, int, sig,
	 siginfo_t __user *, uinfo)
 */
#include <signal.h>
#include <string.h>
#include "pids.h"
#include "random.h"
#include "sanitise.h"

static void sanitise_rt_tgsigqueueinfo(struct syscallrecord *rec)
{
	siginfo_t *info;

	info = (siginfo_t *) get_writable_address(sizeof(*info));
	memset(info, 0, sizeof(*info));

	info->si_code = SI_QUEUE;
	info->si_pid = getpid();
	info->si_uid = getuid();
	info->si_int = rand32();

	rec->a4 = (unsigned long) info;
}

struct syscallentry syscall_rt_tgsigqueueinfo = {
	.name = "rt_tgsigqueueinfo",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_PID, [2] = ARG_RANGE },
	.argname = { [0] = "tgid", [1] = "pid", [2] = "sig", [3] = "uinfo" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = _NSIG,
	.sanitise = sanitise_rt_tgsigqueueinfo,
};
