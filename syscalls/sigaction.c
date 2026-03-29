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

static struct sigaction *alloc_sigaction(void)
{
	struct sigaction *sa;

	sa = (struct sigaction *) get_writable_address(sizeof(*sa));
	sigemptyset(&sa->sa_mask);
	sa->sa_flags = 0;
	sa->sa_handler = RAND_BOOL() ? SIG_DFL : SIG_IGN;
	return sa;
}

static void sanitise_rt_sigaction(struct syscallrecord *rec)
{
	rec->a2 = RAND_BOOL() ? 0 : (unsigned long) alloc_sigaction();
	rec->a3 = RAND_BOOL() ? 0 : (unsigned long) alloc_sigaction();
	rec->a4 = sizeof(sigset_t);
}

struct syscallentry syscall_rt_sigaction = {
	.name = "rt_sigaction",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.sanitise = sanitise_rt_sigaction,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "sig", [1] = "act", [2] = "oact", [3] = "sigsetsize" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = _NSIG,
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
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = _NSIG,
	.flags = AVOID_SYSCALL,
};
