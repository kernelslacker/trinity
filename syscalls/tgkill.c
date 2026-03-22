/*
 * SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig)
 */
#include <signal.h>
#include "sanitise.h"

static unsigned long safe_signals[] = {
	SIGHUP, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
	SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE,
	SIGALRM, SIGTERM, SIGCHLD, SIGCONT,
	SIGURG, SIGXCPU, SIGXFSZ, SIGVTALRM,
	SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

struct syscallentry syscall_tgkill = {
	.name = "tgkill",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.arg1name = "tgid",
	.arg1type = ARG_PID,
	.arg2name = "pid",
	.arg2type = ARG_PID,
	.arg3name = "sig",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(safe_signals),
	.flags = AVOID_SYSCALL,
};
