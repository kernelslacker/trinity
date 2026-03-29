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

static void sanitise_shmctl(struct syscallrecord *rec)
{
	switch (rec->a2) {
	case IPC_RMID:
	case SHM_LOCK:
	case SHM_UNLOCK:
		rec->a3 = 0;
		break;
	case IPC_INFO:
		rec->a3 = (unsigned long) zmalloc(sizeof(struct shminfo));
		break;
	case SHM_INFO:
		rec->a3 = (unsigned long) zmalloc(sizeof(struct shm_info));
		break;
	default:
		/* IPC_STAT, IPC_SET, SHM_STAT */
		rec->a3 = (unsigned long) zmalloc(sizeof(struct shmid_ds));
		break;
	}
}

static void post_shmctl(struct syscallrecord *rec)
{
	freeptr(&rec->a3);
}

struct syscallentry syscall_shmctl = {
	.name = "shmctl",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "shmid", [1] = "cmd", [2] = "buf" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].list = ARGLIST(shmctl_ops),
	.sanitise = sanitise_shmctl,
	.post = post_shmctl,
};
