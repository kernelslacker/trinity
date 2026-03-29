/*
 * SYSCALL_DEFINE2(signal, int, sig, __sighandler_t, handler)
 */
#include <signal.h>
#include "sanitise.h"

struct syscallentry syscall_signal = {
	.name = "signal",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "sig", [1] = "handler" },
	.low1range = 0,
	.hi1range = _NSIG,
	.flags = AVOID_SYSCALL,
};
