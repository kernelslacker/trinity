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
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "msqid", [1] = "msgp", [2] = "msgsz", [3] = "msgflg" },
	.low1range = 0,
	.hi1range = 65535,
	.arg4list = ARGLIST(msgsnd_flags),
	.flags = NEED_ALARM,
};
