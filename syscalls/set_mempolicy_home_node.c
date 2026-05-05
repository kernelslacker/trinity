/*
 * SYSCALL_DEFINE4(set_mempolicy_home_node, unsigned long, start, unsigned long, len, unsigned long, home_node, unsigned long, flags)
 */
#include "sanitise.h"

static void sanitise_set_mempolicy_home_node(struct syscallrecord *rec)
{
	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	rec->a4 = 0;	// no flags right now
}

struct syscallentry syscall_set_mempolicy_home_node = {
	.name = "set_mempolicy_home_node",
	.num_args = 4,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_RANGE },
	.argname = { [0] = "start", [1] = "len", [2] = "home_node", [3] = "flags" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 7,
	.sanitise = sanitise_set_mempolicy_home_node,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
};
