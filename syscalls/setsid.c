/*
 * SYSCALL_DEFINE0(setsid)
 */
#include "sanitise.h"

struct syscallentry syscall_setsid = {
	.name = "setsid",
	.num_args = 0,
};
