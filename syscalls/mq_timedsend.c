/*
 * SYSCALL_DEFINE5(mq_timedsend, mqd_t, mqdes, const char __user *, u_msg_ptr,
	size_t, msg_len, unsigned int, msg_prio,
	const struct timespec __user *, u_abs_timeout)
 */
#include "sanitise.h"

struct syscallentry syscall_mq_timedsend = {
	.name = "mq_timedsend",
	.group = GROUP_IPC,
	.num_args = 5,
	.argtype = { [0] = ARG_FD_MQ, [1] = ARG_BUF_SIZED, [2] = ARG_BUF_LEN, [3] = ARG_RANGE, [4] = ARG_TIMESPEC },
	.argname = { [0] = "mqdes", [1] = "u_msg_ptr", [2] = "msg_len", [3] = "msg_prio", [4] = "u_abs_timeout" },
	.arg_params[3].range.low = 0,
	.arg_params[3].range.hi = 32768,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
