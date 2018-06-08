/*
 * SYSCALL_DEFINE6(ipc, unsigned int, call, int, first, unsigned long, second,
                  unsigned long, third, void __user *, ptr, long, fifth)
 */
#include <linux/ipc.h>
#include "sanitise.h"

static unsigned long ipc_calls[] = {
	SEMOP, SEMGET, SEMCTL, SEMTIMEDOP,
	MSGSND, MSGRCV, MSGGET, MSGCTL,
	SHMAT, SHMDT, SHMGET, SHMCTL,
};

struct syscallentry syscall_ipc = {
	.name = "ipc",
	.num_args = 6,
	.arg1name = "call",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(ipc_calls),
	.arg2name = "first",
	.arg3name = "second",
	.arg4name = "third",
	.arg5name = "ptr",
	.arg5type = ARG_ADDRESS,
	.arg6name = "fifth",
	.flags = IGNORE_ENOSYS,
};
