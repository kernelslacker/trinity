/*
 * SYSCALL_DEFINE4(rt_sigaction, int, sig,
	const struct sigaction __user *, act,
	struct sigaction __user *, oact,
	size_t, sigsetsize)
 */
#include <signal.h>
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_rt_sigaction(struct syscallrecord *rec)
{
	if (RAND_BOOL())
		rec->a2 = 0;

	if (RAND_BOOL())
		rec->a3 = 0;

	rec->a4 = sizeof(sigset_t);
}

struct syscallentry syscall_rt_sigaction = {
	.name = "rt_sigaction",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.sanitise = sanitise_rt_sigaction,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "sig", [1] = "act", [2] = "oact", [3] = "sigsetsize" },
	.low1range = 0,
	.hi1range = _NSIG,
};


/*
 * asmlinkage int
   sys_sigaction(int sig, const struct old_sigaction __user *act,
   struct old_sigaction __user *oact)
 */

struct syscallentry syscall_sigaction = {
	.name = "sigaction",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.sanitise = sanitise_rt_sigaction,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "sig", [1] = "act", [2] = "oact" },
	.low1range = 0,
	.hi1range = _NSIG,
	.flags = AVOID_SYSCALL,
};
