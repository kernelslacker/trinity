/*
 * SYSCALL_DEFINE5(get_mempolicy, int __user *, policy,
	unsigned long __user *, nmask, unsigned long, maxnode,
	unsigned long, addr, unsigned long, flags)
 */

#define MPOL_F_NODE     (1<<0)  /* return next IL mode instead of node mask */
#define MPOL_F_ADDR     (1<<1)  /* look up vma using address */
#define MPOL_F_MEMS_ALLOWED (1<<2) /* return allowed memories */

#include "sanitise.h"

static unsigned long get_mempolicy_flags[] = {
	MPOL_F_NODE, MPOL_F_ADDR, MPOL_F_MEMS_ALLOWED,
};

static void sanitise_get_mempolicy(struct syscallrecord *rec)
{
	unsigned long maxnode = rec->a3;
	unsigned long nmask_bytes;

	/*
	 * The kernel writes an int through policy (a1) and up to maxnode
	 * bits through nmask (a2).  Both args are ARG_ADDRESS, so the
	 * random-address pool sources them with no overlap check against
	 * the alloc_shared regions.  nmask_bytes is BITS_TO_LONGS rounded
	 * up to whole longs; bound it to a sane page in case maxnode came
	 * out at the high end of its range.
	 */
	avoid_shared_buffer(&rec->a1, sizeof(int));
	nmask_bytes = ((maxnode + 63) / 64) * sizeof(long);
	if (nmask_bytes == 0)
		nmask_bytes = sizeof(long);
	avoid_shared_buffer(&rec->a2, nmask_bytes);
}

struct syscallentry syscall_get_mempolicy = {
	.name = "get_mempolicy",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_MMAP, [4] = ARG_LIST },
	.argname = { [0] = "policy", [1] = "nmask", [2] = "maxnode", [3] = "addr", [4] = "flags" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 1 << 9,	/* 1 << CONFIG_NODES_SHIFT */
	.arg_params[4].list = ARGLIST(get_mempolicy_flags),
	.sanitise = sanitise_get_mempolicy,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
};
