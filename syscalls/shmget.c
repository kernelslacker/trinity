/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "sanitise.h"
#include "shm.h"

static void post_shmget(int childno)
{
	if (shm->retval[childno] == (unsigned long) -1L)
		return;

	shmctl(shm->retval[childno], IPC_RMID, NULL);
}

struct syscallentry syscall_shmget = {
	.name = "shmget",
	.num_args = 3,
	.arg1name = "key",
	.arg2name = "size",
	.arg2type = ARG_LEN,
	.arg3name = "shmflg",
	.post = post_shmget,
};
