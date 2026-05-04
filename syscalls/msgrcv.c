/*
 * SYSCALL_DEFINE5(msgrcv, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, long, msgtyp, int, msgflg)
 */
#include <sys/types.h>
#include <linux/msg.h>
#include "compat.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static void sanitise_msgrcv(struct syscallrecord *rec)
{
	rec->a3 = rand() % MSGMAX;
	avoid_shared_buffer(&rec->a2, rec->a3 + sizeof(long));
}

static void post_msgrcv(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || (size_t) ret > (size_t) rec->a3)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

static unsigned long msgrcv_flags[] = {
	MSG_NOERROR, MSG_EXCEPT, MSG_COPY, IPC_NOWAIT,
};

struct syscallentry syscall_msgrcv = {
	.name = "msgrcv",
	.group = GROUP_IPC,
	.num_args = 5,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_NON_NULL_ADDRESS, [3] = ARG_RANGE, [4] = ARG_LIST },
	.argname = { [0] = "msqid", [1] = "msgp", [2] = "msgsz", [3] = "msgtyp", [4] = "msgflg" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[3].range.low = 0,
	.arg_params[3].range.hi = 10,
	.arg_params[4].list = ARGLIST(msgrcv_flags),
	.flags = IGNORE_ENOSYS | NEED_ALARM,
	.sanitise = sanitise_msgrcv,
	.post = post_msgrcv,
};
