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

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
		rec->a3 = 0;
		return;
	case IPC_INFO:
	case MSG_INFO:
		buf = zmalloc(sizeof(struct msginfo));
		break;
	default:
		/* IPC_STAT, IPC_SET, MSG_STAT */
		buf = zmalloc(sizeof(struct msqid_ds));
		break;
	}

	rec->a3 = (unsigned long) buf;
	/* Snapshot for the post handler -- a3 may be scribbled by a sibling
	 * syscall before post_msgctl() runs. */
	rec->post_state = (unsigned long) buf;
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
	.argtype = { [0] = ARG_RANGE, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "msqid", [1] = "cmd", [2] = "buf" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].list = ARGLIST(msgctl_cmds),
	.sanitise = sanitise_msgctl,
	.post = post_msgctl,
};
