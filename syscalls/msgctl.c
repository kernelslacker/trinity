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
	.argtype = { [0] = ARG_RANGE, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "msqid", [1] = "cmd", [2] = "buf" },
	.low1range = 0,
	.hi1range = 65535,
	.arg2list = ARGLIST(msgctl_cmds),
};
