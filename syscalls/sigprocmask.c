/*
 * SYSCALL_DEFINE3(sigprocmask, int, how, old_sigset_t __user *, set,
                 old_sigset_t __user *, oset)
 */
#include <signal.h>
#include "sanitise.h"

static unsigned long sigprocmask_how[] = {
	SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK,
};

static void sanitise_sigprocmask(struct syscallrecord *rec)
{
	/*
	 * oset (a3) is the kernel's writeback target for the previous mask.
	 * sigprocmask predates rt_sigprocmask and uses old_sigset_t, which
	 * is one word; sigset_t is the conservative upper bound.
	 */
	avoid_shared_buffer(&rec->a3, sizeof(sigset_t));
}

struct syscallentry syscall_sigprocmask = {
	.name = "sigprocmask",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "how", [1] = "set", [2] = "oset" },
	.arg_params[0].list = ARGLIST(sigprocmask_how),
	.sanitise = sanitise_sigprocmask,
};
