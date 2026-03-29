/*
 * SYSCALL_DEFINE4(futex_wake, void __user *, uaddr,
 *		unsigned long, mask, int, nr, unsigned int, flags)
 */
#include "random.h"
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

static void sanitise_futex_wake(struct syscallrecord *rec)
{
	/* mask: generate a useful comparison mask */
	switch (rand() % 4) {
	case 0: rec->a2 = 0xffffffff; break;	/* all bits (common case) */
	case 1: rec->a2 = 0xff; break;		/* U8 futex */
	case 2: rec->a2 = 0xffff; break;	/* U16 futex */
	default: rec->a2 = rand32(); break;	/* random mask */
	}
}

struct syscallentry syscall_futex_wake = {
	.name = "futex_wake",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_LIST },
	.argname = { [0] = "uaddr", [1] = "mask", [2] = "nr", [3] = "flags" },
	.low3range = 1,
	.hi3range = 128,
	.arg4list = ARGLIST(futex2_flags),
	.sanitise = sanitise_futex_wake,
	.group = GROUP_IPC,
};
