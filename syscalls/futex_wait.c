/*
 * SYSCALL_DEFINE6(futex_wait, void __user *, uaddr,
 *		unsigned long, val, unsigned long, mask,
 *		unsigned int, flags,
 *		struct __kernel_timespec __user *, timeout,
 *		clockid_t, clockid)
 */
#include <time.h>
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

#ifndef FUTEX2_MPOL
#define FUTEX2_MPOL		0x08
#endif

static unsigned long futex2_flags[] = {
	FUTEX2_SIZE_U8, FUTEX2_SIZE_U16, FUTEX2_SIZE_U32, FUTEX2_SIZE_U64,
	FUTEX2_NUMA, FUTEX2_PRIVATE, FUTEX2_MPOL,
};

static unsigned long futex_wait_clockids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC,
};

static void sanitise_futex_wait(struct syscallrecord *rec)
{
	/* val: write a known value to uaddr so the comparison can succeed */
	__u32 *futex_word;

	futex_word = (__u32 *) get_writable_struct(sizeof(*futex_word));
	if (!futex_word)
		return;
	*futex_word = rand32();
	rec->a1 = (unsigned long) futex_word;
	rec->a2 = *futex_word;	/* match the value we just wrote */

	/* mask: generate a useful comparison mask */
	switch (rand() % 4) {
	case 0: rec->a3 = 0xffffffff; break;	/* all bits (common case) */
	case 1: rec->a3 = 0xff; break;		/* U8 futex */
	case 2: rec->a3 = 0xffff; break;	/* U16 futex */
	default: rec->a3 = rand32(); break;	/* random mask */
	}

	/* timeout: sometimes provide a short timeout */
	if (RAND_BOOL()) {
		struct timespec *ts;

		ts = (struct timespec *) get_writable_struct(sizeof(*ts));
		if (!ts)
			return;
		ts->tv_sec = 0;
		ts->tv_nsec = rand() % 1000000;	/* up to 1ms */
		rec->a5 = (unsigned long) ts;
	}
}

struct syscallentry syscall_futex_wait = {
	.name = "futex_wait",
	.num_args = 6,
	.argtype = { [0] = ARG_ADDRESS, [3] = ARG_LIST, [4] = ARG_ADDRESS, [5] = ARG_OP },
	.argname = { [0] = "uaddr", [1] = "val", [2] = "mask", [3] = "flags", [4] = "timeout", [5] = "clockid" },
	.arg_params[3].list = ARGLIST(futex2_flags),
	.arg_params[5].list = ARGLIST(futex_wait_clockids),
	.sanitise = sanitise_futex_wait,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_IPC,
};
