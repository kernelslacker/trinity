/*
 * SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
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

struct syscallentry syscall_kill = {
	.name = "kill",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "sig",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(safe_signals),
	.flags = AVOID_SYSCALL,
};
