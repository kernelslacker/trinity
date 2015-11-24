/*
 * SYSCALL_DEFINE3(signalfd, int, ufd, sigset_t __user *, user_mask, size_t, sizemask)
 */
#include "sanitise.h"

struct syscallentry syscall_signalfd = {
	.name = "signalfd",
	.num_args = 3,
	.arg1name = "ufd",
	.arg1type = ARG_FD,
	.arg2name = "user_mask",
	.arg2type = ARG_ADDRESS,
	.arg3name = "sizemask",
	.arg3type = ARG_LEN,
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
	.num_args = 4,
	.arg1name = "ufd",
	.arg1type = ARG_FD,
	.arg2name = "user_mask",
	.arg2type = ARG_ADDRESS,
	.arg3name = "sizemask",
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(signalfd4_flags),
	.flags = NEED_ALARM,
};
