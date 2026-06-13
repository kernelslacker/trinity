/*
 * SYSCALL_DEFINE5(mq_timedreceive, mqd_t, mqdes, char __user *, u_msg_ptr,
	size_t, msg_len, unsigned int __user *, u_msg_prio,
	const struct timespec __user *, u_abs_timeout)
 */
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_mq_timedreceive(struct syscallrecord *rec)
{
	char *msg;
	unsigned int *prio;
	unsigned int len;

	/* Provide a receive buffer. */
	len = 1 + (rnd_modulo_u32(8192));
	msg = (char *) get_writable_address(len);

	/* Writable priority output. */
	prio = (unsigned int *) get_writable_address(sizeof(*prio));

	if (msg == NULL || prio == NULL)
		return;

	rec->a2 = (unsigned long) msg;
	rec->a3 = len;
	rec->a4 = (unsigned long) prio;

	avoid_shared_buffer_out(&rec->a2, rec->a3);
	avoid_shared_buffer_out(&rec->a4, sizeof(unsigned int));

	/*
	 * a5 (u_abs_timeout) is typed ARG_TIMESPEC; the generator
	 * publishes a writable pool buffer (or NULL ~10%) for us.
	 * NEED_ALARM caps any blocking arm a large tv_sec bucket
	 * would otherwise produce.
	 */
}

struct syscallentry syscall_mq_timedreceive = {
	.name = "mq_timedreceive",
	.group = GROUP_IPC,
	.num_args = 5,
	.argtype = { [0] = ARG_FD_MQ, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_TIMESPEC },
	.argname = { [0] = "mqdes", [1] = "u_msg_ptr", [2] = "msg_len", [3] = "u_msg_prio", [4] = "u_abs_timeout" },
	.flags = NEED_ALARM,
	.sanitise = sanitise_mq_timedreceive,
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
};
