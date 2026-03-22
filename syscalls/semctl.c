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
	.arg1name = "semid",
	.arg1type = ARG_RANGE,
	.low1range = 0,
	.hi1range = 65535,
	.arg2name = "semnum",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 250,
	.arg3name = "cmd",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(semctl_cmds),
	.arg4name = "arg",
	.arg4type = ARG_ADDRESS,
};
