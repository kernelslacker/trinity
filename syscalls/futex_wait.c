/*
 * SYSCALL_DEFINE6(futex_wait, void __user *, uaddr,
 *		unsigned long, val, unsigned long, mask,
 *		unsigned int, flags,
 *		struct __kernel_timespec __user *, timeout,
 *		clockid_t, clockid)
 */
#include <time.h>
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

static unsigned long futex_wait_clockids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC,
};

struct syscallentry syscall_futex_wait = {
	.name = "futex_wait",
	.num_args = 6,
	.arg1name = "uaddr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "val",
	.arg3name = "mask",
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(futex2_flags),
	.arg5name = "timeout",
	.arg5type = ARG_ADDRESS,
	.arg6name = "clockid",
	.arg6type = ARG_OP,
	.arg6list = ARGLIST(futex_wait_clockids),
	.flags = NEED_ALARM,
};
