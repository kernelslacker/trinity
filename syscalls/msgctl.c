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

struct syscallentry syscall_msgctl = {
	.name = "msgctl",
	.group = GROUP_IPC,
	.num_args = 3,
	.arg1name = "msqid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "cmd",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(msgctl_cmds),
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
};
