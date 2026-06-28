/*
 * SYSCALL_DEFINE4(futex_requeue, struct futex_waitv __user *, waiters,
 *		unsigned int, flags, int, nr_wake, int, nr_requeue)
 */
#include <linux/futex.h>
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static void sanitise_futex_requeue(struct syscallrecord *rec)
{
	struct futex_waitv *waiters;
	__u32 *futex_words;
	unsigned int waitv_flags;

	/* futex_requeue takes exactly 2 waiters: [0]=wake source, [1]=requeue target */
	futex_words = (__u32 *) get_writable_address(2 * sizeof(*futex_words));
	if (futex_words == NULL)
		return;
	futex_words[0] = rand32();
	futex_words[1] = rand32();

	waiters = (struct futex_waitv *) get_writable_address(2 * sizeof(*waiters));
	if (waiters == NULL)
		return;
	memset(waiters, 0, 2 * sizeof(*waiters));

	/* Source and destination waitv must share identical flags; otherwise
	 * futex_validate_input() rejects with -EINVAL before any of the
	 * requeue / PI / waiter-walk paths run.
	 */
	waitv_flags = FUTEX2_SIZE_U32;
	if (RAND_BOOL())
		waitv_flags |= FUTEX2_PRIVATE;

	waiters[0].uaddr = (__u64)(unsigned long) &futex_words[0];
	waiters[0].val = futex_words[0];
	waiters[0].flags = waitv_flags;

	waiters[1].uaddr = (__u64)(unsigned long) &futex_words[1];
	waiters[1].val = futex_words[1];
	waiters[1].flags = waitv_flags;

	rec->a1 = (unsigned long) waiters;
	avoid_shared_buffer_inout(&rec->a1, 2 * sizeof(*waiters));
	rec->a2 = 0;	/* no flags defined yet */
}

struct syscallentry syscall_futex_requeue = {
	.name = "futex_requeue",
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [2] = ARG_RANGE, [3] = ARG_RANGE },
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
