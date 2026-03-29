/*
 * SYSCALL_DEFINE3(signalfd, int, ufd, sigset_t __user *, user_mask, size_t, sizemask)
 */
#include "sanitise.h"

struct syscallentry syscall_signalfd = {
	.name = "signalfd",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask" },
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

struct syscallentry syscall_signalfd4 = {
	.name = "signalfd4",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "ufd", [1] = "user_mask", [2] = "sizemask", [3] = "flags" },
	.arg4list = ARGLIST(signalfd4_flags),
	.rettype = RET_FD,
	.flags = NEED_ALARM,
};
