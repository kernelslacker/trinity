/*
 * SYSCALL_DEFINE(semctl)(int semid, int semnum, int cmd, union semun arg)
 */
#include <sys/ipc.h>
#include <sys/sem.h>
#include "sanitise.h"

static unsigned long semctl_cmds[] = {
	IPC_RMID, IPC_SET, IPC_STAT, IPC_INFO,
	GETPID, GETVAL, GETALL, GETNCNT, GETZCNT,
	SETVAL, SETALL,
	SEM_STAT, SEM_INFO, SEM_STAT_ANY,
};

struct syscallentry syscall_semctl = {
	.name = "semctl",
	.group = GROUP_IPC,
	.num_args = 4,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_OP, [3] = ARG_ADDRESS },
	.argname = { [0] = "semid", [1] = "semnum", [2] = "cmd", [3] = "arg" },
	.low1range = 0,
	.hi1range = 65535,
	.low2range = 0,
	.hi2range = 250,
	.arg3list = ARGLIST(semctl_cmds),
};
