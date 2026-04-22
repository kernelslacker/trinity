/*
 * SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
	 siginfo_t __user *, uinfo, const struct timespec __user *, uts,
	 size_t, sigsetsize)
 */
#include <signal.h>
#include <time.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_rt_sigtimedwait(struct syscallrecord *rec)
{
	sigset_t *set;
	struct timespec *ts;

	set = (sigset_t *) get_writable_address(sizeof(*set));
	sigemptyset(set);
	sigaddset(set, SIGUSR1);
	sigaddset(set, SIGUSR2);
	sigaddset(set, SIGALRM);

	/* short timeout: 0-1ms to avoid blocking */
	ts = (struct timespec *) get_writable_address(sizeof(*ts));
	ts->tv_sec = 0;
	ts->tv_nsec = rand() % 1000000;

	rec->a1 = (unsigned long) set;
	rec->a3 = (unsigned long) ts;
	rec->a4 = sizeof(sigset_t);

	/*
	 * uinfo (a2) is the kernel's writeback target for the siginfo of the
	 * dequeued signal.  ARG_ADDRESS draws from the random pool, so scrub
	 * it against the alloc_shared regions before the syscall is issued.
	 */
	avoid_shared_buffer(&rec->a2, sizeof(siginfo_t));
}

struct syscallentry syscall_rt_sigtimedwait = {
	.name = "rt_sigtimedwait",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "uthese", [1] = "uinfo", [2] = "uts", [3] = "sigsetsize" },
	.sanitise = sanitise_rt_sigtimedwait,
	.flags = NEED_ALARM,
};
