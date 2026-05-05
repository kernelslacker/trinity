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
	.argtype = { [0] = ARG_PID, [1] = ARG_OP },
	.argname = { [0] = "pid", [1] = "sig" },
	.arg_params[1].list = ARGLIST(safe_signals),
	.rettype = RET_ZERO_SUCCESS,
	.flags = AVOID_SYSCALL,
};
