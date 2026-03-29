/*
 * SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg)
 */
#include <sys/ipc.h>
#include "sanitise.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
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
