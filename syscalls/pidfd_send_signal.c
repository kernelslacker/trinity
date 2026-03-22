/*
 *   SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig, siginfo_t __user *, info, unsigned int, flags)
 */
#include <signal.h>
#include "sanitise.h"

static unsigned long pidfd_signals[] = {
	SIGHUP, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
	SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE,
	SIGALRM, SIGTERM, SIGCHLD, SIGCONT,
	SIGURG, SIGXCPU, SIGXFSZ, SIGVTALRM,
	SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

static unsigned long pidfd_send_signal_flags[] = {
	0,
};

struct syscallentry syscall_pidfd_send_signal = {
	.name = "pidfd_send_signal",
	.group = GROUP_PROCESS,
	.num_args = 4,
	.arg1name = "pidfd",
	.arg1type = ARG_FD_PIDFD,
	.arg2name = "sig",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(pidfd_signals),
	.arg3name = "info",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
	.arg4type = ARG_OP,
	.arg4list = ARGLIST(pidfd_send_signal_flags),
};
