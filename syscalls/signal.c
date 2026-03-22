/*
 * SYSCALL_DEFINE2(signal, int, sig, __sighandler_t, handler)
 */
#include <signal.h>
#include "sanitise.h"

struct syscallentry syscall_signal = {
	.name = "signal",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.arg1name = "sig",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = _NSIG,
	.arg2name = "handler",
	.arg2type = ARG_ADDRESS,
	.flags = AVOID_SYSCALL,
};
