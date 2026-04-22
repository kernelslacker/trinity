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

	/*
	 * oset (a3) is the kernel's writeback target for the previous mask
	 * (a4 bytes wide).  ARG_ADDRESS draws from the random pool, so a
	 * fuzzed pointer can land inside an alloc_shared region and let the
	 * kernel scribble bookkeeping.
	 */
	avoid_shared_buffer(&rec->a3, rec->a4);
}

static unsigned long sigprocmask_how[] = {
	SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK,
};

struct syscallentry syscall_rt_sigprocmask = {
	.name = "rt_sigprocmask",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.sanitise = sanitise_rt_sigprocmask,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "how", [1] = "set", [2] = "oset", [3] = "sigsetsize" },
	.arg_params[0].list = ARGLIST(sigprocmask_how),
};
