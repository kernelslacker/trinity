/*
 * SYSCALL_DEFINE3(shmget, key_t, key, size_t, size, int, shmflg)
 */

#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "trinity.h"
#include "sanitise.h"

static void post_shmget(int syscallret)
{
	struct shmid_ds *shmid_ds;

	if (syscallret == -1)
		return;

	shmid_ds = malloc(sizeof(struct shmid_ds));

	shmctl(syscallret, IPC_RMID, shmid_ds);
}

struct syscall syscall_shmget = {
	.name = "shmget",
	.num_args = 3,
	.arg1name = "key",
	.arg2name = "size",
	.arg2type = ARG_LEN,
	.arg3name = "shmflg",
	.post = post_shmget,
};
