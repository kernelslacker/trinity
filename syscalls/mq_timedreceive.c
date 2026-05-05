/*
 * SYSCALL_DEFINE5(mq_timedreceive, mqd_t, mqdes, char __user *, u_msg_ptr,
	size_t, msg_len, unsigned int __user *, u_msg_prio,
	const struct timespec __user *, u_abs_timeout)
 */
#include <time.h>
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_mq_timedreceive(struct syscallrecord *rec)
{
	char *msg;
	unsigned int *prio;
	struct timespec *ts;
	unsigned int len;

	/* Provide a receive buffer. */
	len = 1 + (rand() % 8192);
	msg = (char *) get_writable_address(len);

	/* Writable priority output. */
	prio = (unsigned int *) get_writable_address(sizeof(*prio));

	/* Short timeout to avoid blocking. */
	ts = (struct timespec *) get_writable_address(sizeof(*ts));
	ts->tv_sec = 0;
	ts->tv_nsec = rand() % 1000000;	/* up to 1ms */

	rec->a2 = (unsigned long) msg;
	rec->a3 = len;
	rec->a4 = (unsigned long) prio;
	rec->a5 = (unsigned long) ts;
}

static void post_mq_timedreceive(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || (size_t) ret > (size_t) rec->a3)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_mq_timedreceive = {
	.name = "mq_timedreceive",
	.group = GROUP_IPC,
	.num_args = 5,
	.argtype = { [0] = ARG_FD_MQ },
	.argname = { [0] = "mqdes", [1] = "u_msg_ptr", [2] = "msg_len", [3] = "u_msg_prio", [4] = "u_abs_timeout" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_mq_timedreceive,
	.post = post_mq_timedreceive,
	.bound_arg = 3,
};
