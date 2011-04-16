/*
 * SYSCALL_DEFINE6(mbind, unsigned long, start, unsigned long, len,
	unsigned long, mode, unsigned long __user *, nmask,
	unsigned long, maxnode, unsigned, flags)
 */

#include "../arch.h"

#define MPOL_F_STATIC_NODES     (1 << 15)
#define MPOL_F_RELATIVE_NODES   (1 << 14)

{
	.name = "mbind",
	.num_args = 6,
	.arg1name = "start",
	.arg1type = ARG_ADDRESS,

	.arg2name = "len",
	.arg2type = ARG_LEN,

	.arg3name = "mode",
	.arg3type = ARG_RANGE,
	.low3range = 0,
	.hi3range = 5,

	.arg4name = "nmask",
	.arg4type = ARG_ADDRESS,

	.arg5name = "maxnode",
	.arg5type = ARG_RANGE,
	.low5range = 2,
	.hi5range = PAGE_SIZE * 8,

	.arg6name = "flags",
	.arg6type = ARG_LIST,
	.arg6list = {
		.num = 2,
		.values = { MPOL_F_STATIC_NODES, MPOL_F_RELATIVE_NODES },
	},
},
