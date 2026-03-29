/*
 *   SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig, siginfo_t __user *, info, unsigned int, flags)
 */
#include <signal.h>
#include <linux/pidfd.h>
#include "sanitise.h"

static unsigned long pidfd_signals[] = {
	SIGHUP, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
	SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE,
	SIGALRM, SIGTERM, SIGCHLD, SIGCONT,
	SIGURG, SIGXCPU, SIGXFSZ, SIGVTALRM,
	SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

static unsigned long pidfd_send_signal_flags[] = {
	PIDFD_SIGNAL_THREAD, PIDFD_SIGNAL_THREAD_GROUP, PIDFD_SIGNAL_PROCESS_GROUP,
};

struct syscallentry syscall_pidfd_send_signal = {
	.name = "pidfd_send_signal",
	.group = GROUP_PROCESS,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_PIDFD, [1] = ARG_OP, [2] = ARG_ADDRESS, [3] = ARG_OP },
	.argname = { [0] = "pidfd", [1] = "sig", [2] = "info", [3] = "flags" },
	.arg2list = ARGLIST(pidfd_signals),
	.arg4list = ARGLIST(pidfd_send_signal_flags),
};
