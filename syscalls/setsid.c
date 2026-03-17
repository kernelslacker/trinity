/*
 * SYSCALL_DEFINE0(setsid)
 */
#include "sanitise.h"

struct syscallentry syscall_setsid = {
	.name = "setsid",
	.group = GROUP_PROCESS,
	.num_args = 0,
};
