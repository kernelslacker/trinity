/*
 * SYSCALL_DEFINE0(munlockall)
 */
#include "sanitise.h"

struct syscallentry syscall_munlockall = {
	.name = "munlockall",
	.num_args = 0,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
};
