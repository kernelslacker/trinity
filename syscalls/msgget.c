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
	.arg1name = "key",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "msgflg",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(ipc_flags),
};
