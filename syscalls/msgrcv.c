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
	rec->a3 = rnd() % MSGMAX;
}

static unsigned long msgrcv_flags[] = {
	MSG_NOERROR, MSG_EXCEPT, MSG_COPY, IPC_NOWAIT,
};

struct syscallentry syscall_msgrcv = {
	.name = "msgrcv",
	.num_args = 5,
	.arg1name = "msqid",
	.arg2name = "msgp",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.arg3name = "msgsz",
	.arg4name = "msgtyp",
	.arg5name = "msgflg",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(msgrcv_flags),
	.flags = IGNORE_ENOSYS | NEED_ALARM,
	.sanitise = sanitise_msgrcv,
};
