/*
 * SYSCALL_DEFINE3(msgctl, int, msqid, int, cmd, struct msqid_ds __user *, buf)
 */
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long msgctl_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	MSG_INFO, MSG_STAT,
};

static void sanitise_msgctl(struct syscallrecord *rec)
{
	void *buf = NULL;
	unsigned long allocated_size = 0;

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
		rec->a3 = 0;
		return;
	case IPC_INFO:
	case MSG_INFO:
		allocated_size = sizeof(struct msginfo);
		buf = zmalloc(allocated_size);
		break;
	default:
		/* IPC_STAT, IPC_SET, MSG_STAT */
		allocated_size = sizeof(struct msqid_ds);
		buf = zmalloc(allocated_size);
		break;
	}

	rec->a3 = (unsigned long) buf;
	/* Snapshot for the post handler -- a3 may be scribbled by a sibling
	 * syscall before post_msgctl() runs. */
	rec->post_state = (unsigned long) buf;

	avoid_shared_buffer(&rec->a3, allocated_size);
}

static void post_msgctl(struct syscallrecord *rec)
{
	void *buf = (void *) rec->post_state;

	if (buf == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, buf)) {
		outputerr("post_msgctl: rejected suspicious buf=%p (pid-scribbled?)\n", buf);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a3 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_msgctl = {
	.name = "msgctl",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_MSG_ID, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "msqid", [1] = "cmd", [2] = "buf" },
	.arg_params[1].list = ARGLIST(msgctl_cmds),
	.sanitise = sanitise_msgctl,
	.post = post_msgctl,
};
