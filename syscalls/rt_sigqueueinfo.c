/*
 * SYSCALL_DEFINE3(rt_sigqueueinfo, pid_t, pid, int, sig, siginfo_t __user *, uinfo)
 */
#include <signal.h>
#include <string.h>
#include "pids.h"
#include "random.h"
#include "sanitise.h"

static unsigned long safe_signals[] = {
	SIGHUP, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
	SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE,
	SIGALRM, SIGCHLD, SIGCONT, SIGURG, SIGXCPU, SIGXFSZ,
	SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

static void sanitise_rt_sigqueueinfo(struct syscallrecord *rec)
{
	siginfo_t *info;

	/* Avoid SIGKILL, SIGSTOP, SIGTERM; use safe signals or realtime range. */
	if (RAND_BOOL())
		rec->a2 = RAND_ARRAY(safe_signals);
	else
		rec->a2 = SIGRTMIN + (rand() % (SIGRTMAX - SIGRTMIN + 1));

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
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "sig", [2] = "uinfo" },
	.flags = AVOID_SYSCALL,	/* can disrupt signal handling */
	.sanitise = sanitise_rt_sigqueueinfo,
};
