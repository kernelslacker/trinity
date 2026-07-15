/*
 * SYSCALL_DEFINE2(rt_sigsuspend, sigset_t __user *, unewset, size_t, sigsetsize)
 */
#include "random.h"
#include "sanitise.h"
#include "trinity.h"

/* Kernel sigset_t is a fixed 64-bit mask; sizeof matches on every arch. */
#define KERNEL_SIGSET_SIZE	8

/*
 * Bias sigsetsize to the kernel-ABI value (8 bytes = _NSIG/8); keep a
 * small wrong-size arm to hold the EINVAL branch warm.  glibc's
 * sizeof(sigset_t) is 128, and rt_sigsuspend() unconditionally rejects
 * any sigsetsize != sizeof(sigset_t) (kernel-side, 8 bytes) before it
 * touches unewset -- so leaving a2 to ARG_LEN wastes nearly every call
 * on an EINVAL that never reaches the copy_from_user() / set_current_
 * blocked() / schedule() suspend path the syscall exists to exercise.
 */
static void sanitise_rt_sigsuspend(struct syscallrecord *rec)
{
	if (!ONE_IN(8))
		rec->a2 = KERNEL_SIGSET_SIZE;
}

struct syscallentry syscall_rt_sigsuspend = {
	.name = "rt_sigsuspend",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.sanitise = sanitise_rt_sigsuspend,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "unewset", [1] = "sigsetsize" },
	.flags = AVOID_SYSCALL | NEED_ALARM,
};
