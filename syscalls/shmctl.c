/*
 * SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
 */
#include <linux/ipc.h>
#include <linux/shm.h>
#include "ipc-common.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long shmctl_ops[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	SHM_INFO, SHM_STAT, SHM_LOCK, SHM_UNLOCK,
};

static void sanitise_shmctl(struct syscallrecord *rec)
{
	void *buf;
	unsigned long allocated_size;

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
	case SHM_LOCK:
	case SHM_UNLOCK:
		rec->a3 = 0;
		return;
	case IPC_INFO:
		allocated_size = sizeof(struct shminfo);
		break;
	case SHM_INFO:
		allocated_size = sizeof(struct shm_info);
		break;
	default:
		/* IPC_STAT, IPC_SET, SHM_STAT */
		allocated_size = sizeof(struct shmid_ds);
		break;
	}

	buf = zmalloc_tracked(allocated_size);
	rec->a3 = (unsigned long) buf;

	ipcctl_post_state_alloc(rec, buf, allocated_size);

	avoid_shared_buffer_out(&rec->a3, allocated_size);
}

static void post_shmctl(struct syscallrecord *rec)
{
	post_ipcctl_buf_free(rec, "post_shmctl");
}

struct syscallentry syscall_shmctl = {
	.name = "shmctl",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_SYSV_SHM, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "shmid", [1] = "cmd", [2] = "buf" },
	.arg_params[1].list = ARGLIST(shmctl_ops),
	.sanitise = sanitise_shmctl,
	.post = post_shmctl,
};
