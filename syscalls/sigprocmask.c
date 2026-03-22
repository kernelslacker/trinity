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
	.arg1name = "how",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(sigprocmask_how),
	.arg2name = "set",
	.arg2type = ARG_ADDRESS,
	.arg3name = "oset",
};
