/*
 * SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg)
 */
#include <sys/ipc.h>
#include <sys/msg.h>
#include "sanitise.h"
#include "trinity.h"

static void post_msgget(struct syscallrecord *rec)
{
	if (rec->retval == (unsigned long) -1L)
		return;

	msgctl((int) rec->retval, IPC_RMID, NULL);
}

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
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].list = ARGLIST(ipc_flags),
	.post = post_msgget,
};
