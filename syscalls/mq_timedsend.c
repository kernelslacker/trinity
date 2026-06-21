/*
 * SYSCALL_DEFINE5(mq_timedsend, mqd_t, mqdes, const char __user *, u_msg_ptr,
	size_t, msg_len, unsigned int, msg_prio,
	const struct timespec __user *, u_abs_timeout)
 */
#include "objects.h"
#include "sanitise.h"

static void sanitise_mq_timedsend(struct syscallrecord *rec)
{
	struct object *obj;
	int i;

	/*
	 * ARG_FD_MQ plumbed an mq fd into rec->a1 via the pool draw, and
	 * ARG_BUF_SIZED published a coherent (msg_ptr, msg_len) pair into
	 * rec->a2 and rec->a3.  But ARG_BUF_LEN's largest length bucket
	 * reaches 64 KiB while trinity's init_mq_fds() opens every queue
	 * with attr.mq_msgsize = 8192, so the majority of draws short out
	 * at EMSGSIZE inside the kernel's size check before reaching the
	 * per-queue spinlock + msg_insert / wake-waiter path that carries
	 * the real send-side coverage -- "high calls, low edges" cold
	 * shape that the wall-lever shadow gate keeps re-flagging.
	 *
	 * Re-resolve any live mq object from the OBJ_FD_MQ pool (every
	 * queue in the pool shares the same init-time attrs today, so
	 * the specific draw does not need to match the source obj for
	 * rec->a1) and clamp msg_len to its attr_msgsize.  Best-effort:
	 * if the pool is empty or every retry races a destructor leave
	 * the slot alone -- the original ARG_BUF_SIZED draw stays in
	 * place and the EMSGSIZE arm is what we already had.
	 */
	for (i = 0; i < 16; i++) {
		obj = get_random_object(OBJ_FD_MQ, OBJ_GLOBAL);
		if (!objpool_check(obj, OBJ_FD_MQ))
			continue;
		if (obj->mqobj.attr_msgsize <= 0)
			continue;
		if (rec->a3 > (unsigned long) obj->mqobj.attr_msgsize)
			rec->a3 = (unsigned long) obj->mqobj.attr_msgsize;
		return;
	}
}

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
	.sanitise = sanitise_mq_timedsend,
};
