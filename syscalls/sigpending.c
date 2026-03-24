/*
 * SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, set)
 */
#include "sanitise.h"

struct syscallentry syscall_sigpending = {
	.name = "sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 1,
	.arg1name = "set",
	.arg1type = ARG_NON_NULL_ADDRESS,
};
