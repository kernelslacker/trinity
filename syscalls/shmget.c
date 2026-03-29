/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static unsigned long ipc_flags[] = {
	IPC_CREAT, IPC_EXCL,
};

static void post_shmget(struct syscallrecord *rec)
{
	if (rec->retval == (unsigned long) -1L)
		return;

	shmctl(rec->retval, IPC_RMID, NULL);
}

struct syscallentry syscall_shmget = {
	.name = "shmget",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "key", [1] = "size", [2] = "shmflg" },
	.low1range = 0,
	.hi1range = 65535,
	.arg3list = ARGLIST(ipc_flags),
	.post = post_shmget,
};
