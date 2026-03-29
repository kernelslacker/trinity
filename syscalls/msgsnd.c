/*
 * SYSCALL_DEFINE4(msgsnd, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, int, msgflg)
 */
#include <stddef.h>
#include <sys/types.h>
#include <linux/msg.h>
#include "compat.h"
#include "sanitise.h"

static unsigned long msgsnd_flags[] = {
	MSG_NOERROR, MSG_EXCEPT, MSG_COPY, IPC_NOWAIT,
};

static void sanitise_msgsnd(struct syscallrecord *rec)
{
	struct msgbuf *msgp;
	size_t msgsz = rand() % 256;

	msgp = zmalloc(sizeof(struct msgbuf) + msgsz);
	msgp->mtype = (rand() % 255) + 1;	/* mtype must be > 0 */
	rec->a2 = (unsigned long) msgp;
	rec->a3 = msgsz;
}

static void post_msgsnd(struct syscallrecord *rec)
{
	freeptr(&rec->a2);
}

struct syscallentry syscall_msgsnd = {
	.name = "msgsnd",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "msqid", [1] = "msgp", [2] = "msgsz", [3] = "msgflg" },
	.low1range = 0,
	.hi1range = 65535,
	.arg4list = ARGLIST(msgsnd_flags),
	.flags = NEED_ALARM,
	.sanitise = sanitise_msgsnd,
	.post = post_msgsnd,
};
