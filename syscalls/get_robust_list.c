/*
 * SYSCALL_DEFINE3(get_robust_list, int, pid,
	struct robust_list_head __user * __user *, head_ptr,
	size_t __user *, len_ptr)
 */
#include <stddef.h>
#include "sanitise.h"

static void sanitise_get_robust_list(struct syscallrecord *rec)
{
	/*
	 * The kernel writes a robust_list_head pointer through head_ptr (a2)
	 * and a size_t through len_ptr (a3).  Both args are
	 * ARG_NON_NULL_ADDRESS, so generic_sanitise sources them from the
	 * random pool with no overlap check against the alloc_shared regions.
	 */
	avoid_shared_buffer(&rec->a2, sizeof(void *));
	avoid_shared_buffer(&rec->a3, sizeof(size_t));
}

struct syscallentry syscall_get_robust_list = {
	.name = "get_robust_list",
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "head_ptr", [2] = "len_ptr" },
	.sanitise = sanitise_get_robust_list,
	.group = GROUP_PROCESS,
};
