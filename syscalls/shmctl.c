/*
 * SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
 */
#include <linux/ipc.h>
#include <linux/shm.h>
#include "sanitise.h"

static unsigned long shmctl_ops[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	SHM_INFO, SHM_STAT, SHM_LOCK, SHM_UNLOCK,
};

struct syscallentry syscall_shmctl = {
	.name = "shmctl",
	.num_args = 3,
	.arg1name = "shmid",
	.arg2name = "cmd",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(shmctl_ops),
	.arg3name = "buf",
	.arg3type = ARG_ADDRESS,
};
