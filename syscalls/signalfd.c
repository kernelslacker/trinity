/*
 * SYSCALL_DEFINE3(signalfd, int, ufd, sigset_t __user *, user_mask, size_t, sizemask)
 */
#include <signal.h>
#include "sanitise.h"

static void sanitise_signalfd(struct syscallrecord *rec)
{
	sigset_t *set;

	set = (sigset_t *) get_writable_address(sizeof(*set));
	sigemptyset(set);
	sigaddset(set, SIGUSR1);
	sigaddset(set, SIGUSR2);

	rec->a2 = (unsigned long) set;
	rec->a3 = sizeof(sigset_t);
}

struct syscallentry syscall_signalfd = {
	.name = "signalfd",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask" },
	.sanitise = sanitise_signalfd,
	.rettype = RET_FD,
	.flags = NEED_ALARM,
};

/*
 * SYSCALL_DEFINE4(signalfd4, int, ufd, sigset_t __user *, user_mask,
	 size_t, sizemask, int, flags)
 */

#define SFD_CLOEXEC 02000000
#define SFD_NONBLOCK 04000

static unsigned long signalfd4_flags[] = {
	SFD_CLOEXEC, SFD_NONBLOCK,
};

static void sanitise_signalfd4(struct syscallrecord *rec)
{
	sigset_t *set;

	set = (sigset_t *) get_writable_address(sizeof(*set));
	sigemptyset(set);
	sigaddset(set, SIGUSR1);
	sigaddset(set, SIGUSR2);

	rec->a2 = (unsigned long) set;
	rec->a3 = sizeof(sigset_t);
}

struct syscallentry syscall_signalfd4 = {
	.name = "signalfd4",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask", [3] = "flags" },
	.arg_params[3].list = ARGLIST(signalfd4_flags),
	.sanitise = sanitise_signalfd4,
	.rettype = RET_FD,
	.flags = NEED_ALARM,
};
