/*
 * SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg)
 */
#include <sys/ipc.h>
#include "sanitise.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT,
	IPC_CREAT | 0600,
	IPC_CREAT | 0644,
	IPC_CREAT | 0666,
	IPC_CREAT | IPC_EXCL | 0600,
	IPC_CREAT | IPC_EXCL | 0644,
	IPC_CREAT | IPC_EXCL | 0666,
};

struct syscallentry syscall_msgget = {
	.name = "msgget",
	.group = GROUP_IPC,
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_LIST },
	.argname = { [0] = "key", [1] = "msgflg" },
	.low1range = 0,
	.hi1range = 65535,
	.arg2list = ARGLIST(ipc_flags),
};
