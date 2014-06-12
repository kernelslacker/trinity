/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

static void post_shmget(struct syscallrecord *rec)
{
	if (rec->retval == (unsigned long) -1L)
		return;

	shmctl(rec->retval, IPC_RMID, NULL);
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
