/*
 * SYSCALL_DEFINE4(futex_requeue, struct futex_waitv __user *, waiters,
 *		unsigned int, flags, int, nr_wake, int, nr_requeue)
 */
#include <linux/futex.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32		0x02
#endif

#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE		FUTEX_PRIVATE_FLAG
#endif

static void sanitise_futex_requeue(struct syscallrecord *rec)
{
	struct futex_waitv *waiters;
	__u32 *futex_words;

	/* futex_requeue takes exactly 2 waiters: [0]=wake source, [1]=requeue target */
	futex_words = (__u32 *) get_writable_address(2 * sizeof(*futex_words));
	futex_words[0] = rand32();
	futex_words[1] = rand32();

	waiters = (struct futex_waitv *) get_writable_address(2 * sizeof(*waiters));
	memset(waiters, 0, 2 * sizeof(*waiters));

	waiters[0].uaddr = (__u64)(unsigned long) &futex_words[0];
	waiters[0].val = futex_words[0];
	waiters[0].flags = FUTEX2_SIZE_U32;
	if (RAND_BOOL())
		waiters[0].flags |= FUTEX2_PRIVATE;

	waiters[1].uaddr = (__u64)(unsigned long) &futex_words[1];
	waiters[1].val = futex_words[1];
	waiters[1].flags = FUTEX2_SIZE_U32;
	if (RAND_BOOL())
		waiters[1].flags |= FUTEX2_PRIVATE;

	rec->a1 = (unsigned long) waiters;
	rec->a2 = 0;	/* no flags defined yet */
}

struct syscallentry syscall_futex_requeue = {
	.name = "futex_requeue",
	.num_args = 4,
	.argtype = { [2] = ARG_RANGE, [3] = ARG_RANGE },
	.argname = { [0] = "waiters", [1] = "flags", [2] = "nr_wake", [3] = "nr_requeue" },
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 128,
	.arg_params[3].range.low = 0,
	.arg_params[3].range.hi = 128,
	.sanitise = sanitise_futex_requeue,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_IPC,
};
