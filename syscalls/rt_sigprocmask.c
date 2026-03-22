/*
 * SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, set,
	sigset_t __user *, oset, size_t, sigsetsize)
 */
#include <signal.h>
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_rt_sigprocmask(struct syscallrecord *rec)
{
	rec->a4 = sizeof(sigset_t);
}

static unsigned long sigprocmask_how[] = {
	SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK,
};

struct syscallentry syscall_rt_sigprocmask = {
	.name = "rt_sigprocmask",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.sanitise = sanitise_rt_sigprocmask,
	.arg1name = "how",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(sigprocmask_how),
	.arg2name = "set",
	.arg2type = ARG_ADDRESS,
	.arg3name = "oset",
	.arg3type = ARG_ADDRESS,
	.arg4name = "sigsetsize",
	.arg4type = ARG_LEN,
};
