/*
 * SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, set,
	sigset_t __user *, oset, size_t, sigsetsize)
 */
#include <signal.h>
#include "trinity.h"
#include "sanitise.h"

static void sanitise_rt_sigprocmask(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		__unused__ unsigned long *a3,
		unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	*a4 = sizeof(sigset_t);
}

struct syscall syscall_rt_sigprocmask = {
	.name = "rt_sigprocmask",
	.num_args = 4,
	.sanitise = sanitise_rt_sigprocmask,
	.arg1name = "how",
	.arg2name = "set",
	.arg2type = ARG_ADDRESS,
	.arg3name = "oset",
	.arg3type = ARG_ADDRESS,
	.arg4name = "sigsetsize",
};
