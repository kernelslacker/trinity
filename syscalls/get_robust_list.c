/*
 * SYSCALL_DEFINE3(get_robust_list, int, pid,
	struct robust_list_head __user * __user *, head_ptr,
	size_t __user *, len_ptr)
 */
#include "sanitise.h"

struct syscallentry syscall_get_robust_list = {
	.name = "get_robust_list",
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "head_ptr", [2] = "len_ptr" },
	.group = GROUP_PROCESS,
};
