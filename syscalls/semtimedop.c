/*
 * SYSCALL_DEFINE4(semtimedop, int, semid, struct sembuf __user *, tsops,
	 unsigned, nsops, const struct timespec __user *, timeout)
 */
#include "sanitise.h"

struct syscallentry syscall_semtimedop = {
	.name = "semtimedop",
	.group = GROUP_IPC,
	.num_args = 4,
	.arg1name = "semid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "tsops",
	.arg2type = ARG_ADDRESS,
	.arg3name = "nsops",
	.arg3type = ARG_LEN,
	.arg4name = "timeout",
	.arg4type = ARG_ADDRESS,
	.flags = NEED_ALARM,
};