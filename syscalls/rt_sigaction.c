/*
 * SYSCALL_DEFINE4(rt_sigaction, int, sig,
	const struct sigaction __user *, act,
	struct sigaction __user *, oact,
	size_t, sigsetsize)
 */
#include <signal.h>
#include <stdlib.h>

#include "trinity.h"
#include "sanitise.h"

void sanitise_rt_sigaction(
		__unused__ unsigned long *a1,
		__unused__ unsigned long *a2,
		__unused__ unsigned long *a3,
		unsigned long *a4,
		__unused__ unsigned long *a5,
		__unused__ unsigned long *a6)
{
	if ((rand() % 2) == 0)
		*a2 = 0;

	if ((rand() % 2) == 0)
		*a3 = 0;

	*a4 = sizeof(sigset_t);
}

struct syscall syscall_rt_sigaction = {
	.name = "rt_sigaction",
	.num_args = 4,
	.sanitise = sanitise_rt_sigaction,
	.arg1name = "sig",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = _NSIG,
	.arg2name = "act",
	.arg2type = ARG_ADDRESS,
	.arg3name = "oact",
	.arg3type = ARG_ADDRESS,
	.arg4name = "sigsetsize",
};
