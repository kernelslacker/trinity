/*
 * SYSCALL_DEFINE3(rt_sigqueueinfo, pid_t, pid, int, sig, siginfo_t __user *, uinfo)
 */
#include <signal.h>
#include <string.h>
#include "pids.h"
#include "random.h"
#include "sanitise.h"

static void sanitise_rt_sigqueueinfo(struct syscallrecord *rec)
{
	siginfo_t *info;

	info = (siginfo_t *) get_writable_address(sizeof(*info));
	memset(info, 0, sizeof(*info));

	/* Kernel requires si_code to be SI_QUEUE (or < 0 for user-generated). */
	info->si_code = SI_QUEUE;
	info->si_pid = getpid();
	info->si_uid = getuid();
	info->si_int = rand32();

	rec->a3 = (unsigned long) info;
}

struct syscallentry syscall_rt_sigqueueinfo = {
	.name = "rt_sigqueueinfo",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "sig",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = _NSIG,
	.arg3name = "uinfo",
	.flags = AVOID_SYSCALL,	/* can disrupt signal handling */
	.sanitise = sanitise_rt_sigqueueinfo,
};
