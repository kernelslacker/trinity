/*
 * SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, set)
 */
#include "sanitise.h"

struct syscallentry syscall_sigpending = {
	.name = "sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "set" },
};
