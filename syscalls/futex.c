/*
 * SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
	 struct timespec __user *, utime, u32 __user *, uaddr2, u32, val3)
 */
#include <linux/futex.h>
#include "sanitise.h"

static unsigned long futex_ops[] = {
	FUTEX_WAIT, FUTEX_WAKE, FUTEX_FD, FUTEX_REQUEUE,
	FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP, FUTEX_LOCK_PI,
	FUTEX_UNLOCK_PI, FUTEX_TRYLOCK_PI, FUTEX_WAIT_BITSET,
	FUTEX_WAKE_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_CMP_REQUEUE_PI,
	FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE, FUTEX_REQUEUE_PRIVATE,
	FUTEX_CMP_REQUEUE_PRIVATE, FUTEX_WAKE_OP_PRIVATE, FUTEX_LOCK_PI_PRIVATE,
	FUTEX_UNLOCK_PI_PRIVATE, FUTEX_TRYLOCK_PI_PRIVATE,
	FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAKE_BITSET_PRIVATE,
	FUTEX_WAIT_REQUEUE_PI_PRIVATE,
};

struct syscallentry syscall_futex = {
	.name = "futex",
	.num_args = 6,
	.arg1name = "uaddr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "op",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(futex_ops),
	.arg3name = "val",
	.arg4name = "utime",
	.arg4type = ARG_ADDRESS,
	.arg5name = "uaddr2",
	.arg5type = ARG_ADDRESS,
	.arg6name = "val3",
	.rettype = RET_FD,		// FIXME: Needs to mutate depending on 'op' value
	.flags = NEED_ALARM | IGNORE_ENOSYS,
};
