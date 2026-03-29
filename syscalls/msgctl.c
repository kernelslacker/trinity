/*
 * SYSCALL_DEFINE3(msgctl, int, msqid, int, cmd, struct msqid_ds __user *, buf)
 */
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "sanitise.h"

static unsigned long msgctl_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	MSG_INFO, MSG_STAT,
};

static void sanitise_msgctl(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case IPC_RMID:
		rec->a3 = 0;
		break;
	case IPC_INFO:
	case MSG_INFO:
		rec->a3 = (unsigned long) zmalloc(sizeof(struct msginfo));
		break;
	default:
		/* IPC_STAT, IPC_SET, MSG_STAT */
		rec->a3 = (unsigned long) zmalloc(sizeof(struct msqid_ds));
		break;
	}
}

static void post_msgctl(struct syscallrecord *rec)
{
	freeptr(&rec->a3);
}

struct syscallentry syscall_msgctl = {
	.name = "msgctl",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "msqid", [1] = "cmd", [2] = "buf" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].list = ARGLIST(msgctl_cmds),
	.sanitise = sanitise_msgctl,
	.post = post_msgctl,
};
