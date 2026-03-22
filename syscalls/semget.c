/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include <sys/ipc.h>
#include "sanitise.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
};

struct syscallentry syscall_semget = {
	.name = "semget",
	.group = GROUP_IPC,
	.num_args = 3,
	.arg1name = "key",
	.arg2name = "nsems",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 250,
	.arg3name = "semflg",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(ipc_flags),
};
