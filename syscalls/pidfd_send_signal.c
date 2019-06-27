/*
 *   SYSCALL_DEFINE4(pidfd_send_signal, int, pidfd, int, sig, siginfo_t __user *, info, unsigned int, flags)
 */
#include "sanitise.h"

static unsigned long pidfd_send_signal_flags[] = {
	0,
};

struct syscallentry syscall_pidfd_send_signal = {
	.name = "pidfd_send_signal",
	.num_args = 4,
	.arg1name = "pidfd",
	.arg1type = ARG_FD,
	.arg2name = "sig",
	.arg3name = "info",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
	.arg4type = ARG_OP,
	.arg4list = ARGLIST(pidfd_send_signal_flags),
};
