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

struct syscallentry syscall_get_mempolicy = {
	.name = "get_mempolicy",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_MMAP, [4] = ARG_LIST },
	.argname = { [0] = "policy", [1] = "nmask", [2] = "maxnode", [3] = "addr", [4] = "flags" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 1 << 9,	/* 1 << CONFIG_NODES_SHIFT */
	.arg_params[4].list = ARGLIST(get_mempolicy_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
};
