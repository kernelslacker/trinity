/*
 * SYSCALL_DEFINE3(sigprocmask, int, how, old_sigset_t __user *, set,
                 old_sigset_t __user *, oset)
 */
#include <signal.h>
#include "sanitise.h"

static unsigned long sigprocmask_how[] = {
	SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK,
};

struct syscallentry syscall_sigprocmask = {
	.name = "sigprocmask",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "how", [1] = "set", [2] = "oset" },
	.arg_params[0].list = ARGLIST(sigprocmask_how),
};
