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
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_LIST },
	.argname = { [0] = "key", [1] = "nsems", [2] = "semflg" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 250,
	.arg3list = ARGLIST(ipc_flags),
};
