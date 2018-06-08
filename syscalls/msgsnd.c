/*
 * SYSCALL_DEFINE4(msgsnd, int, msqid, struct msgbuf __user *, msgp, size_t, msgsz, int, msgflg)
 */
#include <sys/types.h>
#include <linux/msg.h>
#include "compat.h"
#include "sanitise.h"

static unsigned long msgsnd_flags[] = {
	MSG_NOERROR, MSG_EXCEPT, MSG_COPY, IPC_NOWAIT,
};

struct syscallentry syscall_msgsnd = {
	.name = "msgsnd",
	.num_args = 4,
	.arg1name = "msqid",
	.arg2name = "msgp",
	.arg2type = ARG_ADDRESS,
	.arg3name = "msgsz",
	.arg3type = ARG_LEN,
	.arg4name = "msgflg",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(msgsnd_flags),
};
