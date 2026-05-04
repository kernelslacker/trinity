/*
 * SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
 */
#include <linux/ipc.h>
#include <linux/shm.h>
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long shmctl_ops[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	SHM_INFO, SHM_STAT, SHM_LOCK, SHM_UNLOCK,
};

static void sanitise_shmctl(struct syscallrecord *rec)
{
	void *buf = NULL;

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
	case SHM_LOCK:
	case SHM_UNLOCK:
		rec->a3 = 0;
		return;
	case IPC_INFO:
		buf = zmalloc(sizeof(struct shminfo));
		break;
	case SHM_INFO:
		buf = zmalloc(sizeof(struct shm_info));
		break;
	default:
		/* IPC_STAT, IPC_SET, SHM_STAT */
		buf = zmalloc(sizeof(struct shmid_ds));
		break;
	}

	rec->a3 = (unsigned long) buf;
	/* Snapshot for the post handler -- a3 may be scribbled by a sibling
	 * syscall before post_shmctl() runs. */
	rec->post_state = (unsigned long) buf;
}

static void post_shmctl(struct syscallrecord *rec)
{
	void *buf = (void *) rec->post_state;

	if (buf == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, buf)) {
		outputerr("post_shmctl: rejected suspicious buf=%p (pid-scribbled?)\n", buf);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a3 = 0;
	deferred_freeptr(&rec->post_state);
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
