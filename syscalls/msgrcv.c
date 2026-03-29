/*
 * SYSCALL_DEFINE5(msgrcv, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, long, msgtyp, int, msgflg)
 */
#include <sys/types.h>
#include <linux/msg.h>
#include "compat.h"
#include "random.h"
#include "sanitise.h"

static void sanitise_msgrcv(struct syscallrecord *rec)
{
	rec->a3 = rand() % MSGMAX;
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
	.low1range = 0,
	.hi1range = 65535,
	.low4range = 0,
	.hi4range = 10,
	.arg5list = ARGLIST(msgrcv_flags),
	.flags = IGNORE_ENOSYS | NEED_ALARM,
	.sanitise = sanitise_msgrcv,
};
