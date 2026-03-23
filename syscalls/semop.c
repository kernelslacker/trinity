/*
 * SYSCALL_DEFINE3(semop, int, semid, struct sembuf __user *, tsops, unsigned, nsops)
 */
#include "sanitise.h"

struct syscallentry syscall_semop = {
	.name = "semop",
	.group = GROUP_IPC,
	.num_args = 3,
	.arg1name = "semid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "tsops",
	.arg2type = ARG_ADDRESS,
	.arg3name = "nsops",
	.arg3type = ARG_LEN,
	.flags = NEED_ALARM,
};