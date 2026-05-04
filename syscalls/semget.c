/*
 * SYSCALL_DEFINE3(semget, key_t, key, int, nsems, int, semflg)
 */
#include <sys/ipc.h>
#include <sys/sem.h>
#include "sanitise.h"
#include "trinity.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
};

static void post_semget(struct syscallrecord *rec)
{
	if (rec->retval == (unsigned long) -1L)
		return;

	semctl((int) rec->retval, 0, IPC_RMID);
}

struct syscallentry syscall_semget = {
	.name = "semget",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_LIST },
	.argname = { [0] = "key", [1] = "nsems", [2] = "semflg" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 250,
	.arg_params[2].list = ARGLIST(ipc_flags),
	.post = post_semget,
};
