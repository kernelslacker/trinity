/*
 * SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, set, size_t, sigsetsize)
 */
#include "sanitise.h"

static void sanitise_rt_sigpending(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, rec->a2);
}

struct syscallentry syscall_rt_sigpending = {
	.name = "rt_sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "set", [1] = "sigsetsize" },
	.sanitise = sanitise_rt_sigpending,
};
