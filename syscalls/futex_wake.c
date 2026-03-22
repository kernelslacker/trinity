/*
 * SYSCALL_DEFINE4(futex_wake, void __user *, uaddr,
 *		unsigned long, mask, int, nr, unsigned int, flags)
 */
#include "sanitise.h"
#include "compat.h"

#ifndef FUTEX2_SIZE_U8
#define FUTEX2_SIZE_U8		0x00
#define FUTEX2_SIZE_U16		0x01
#define FUTEX2_SIZE_U32		0x02
#define FUTEX2_SIZE_U64		0x03
#define FUTEX2_NUMA		0x04
#endif

#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE		0x80
#endif

static unsigned long futex2_flags[] = {
	FUTEX2_SIZE_U8, FUTEX2_SIZE_U16, FUTEX2_SIZE_U32, FUTEX2_SIZE_U64,
	FUTEX2_NUMA, FUTEX2_PRIVATE,
};

struct syscallentry syscall_futex_wake = {
	.name = "futex_wake",
	.num_args = 4,
	.arg1name = "uaddr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "mask",
	.arg3name = "nr",
	.arg3type = ARG_RANGE,
	.low3range = 1,
	.hi3range = 128,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(futex2_flags),
	.group = GROUP_IPC,
};
