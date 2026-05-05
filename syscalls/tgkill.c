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
	.argtype = { [0] = ARG_PID, [1] = ARG_PID, [2] = ARG_OP },
	.argname = { [0] = "tgid", [1] = "pid", [2] = "sig" },
	.arg_params[2].list = ARGLIST(safe_signals),
	.rettype = RET_ZERO_SUCCESS,
	.flags = AVOID_SYSCALL,
};
