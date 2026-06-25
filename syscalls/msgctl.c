/*
 * SYSCALL_DEFINE3(msgctl, int, msqid, int, cmd, struct msqid_ds __user *, buf)
 */
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include "ipc-common.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long msgctl_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	MSG_INFO, MSG_STAT, MSG_STAT_ANY,
};

static void sanitise_msgctl(struct syscallrecord *rec)
{
	void *buf;
	unsigned long allocated_size;
	bool input_buf = false;

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
		rec->a3 = 0;
		return;
	case IPC_INFO:
	case MSG_INFO:
		allocated_size = sizeof(struct msginfo);
		buf = zmalloc_tracked(allocated_size);
		break;
	case IPC_SET: {
		/*
		 * IPC_SET copies msg_perm.uid / .gid / .mode out of the
		 * caller-supplied msqid_ds and applies them to the queue's
		 * permission record.  A zeroed buffer leaves uid=gid=0 +
		 * mode=0 which either gets the syscall denied with EPERM
		 * (non-root child can't reassign ownership to root) or
		 * locks the queue out from any subsequent fuzzed operation
		 * with mode 0 -- so the IPC_SET path is effectively a
		 * no-op for coverage.  Populate the perm triple instead.
		 *
		 * Modes come from a tiny dictionary of plausible IPC mode
		 * bits.  Critical: always OR in 0400 so the calling child
		 * keeps read access to the queue after the SET -- without
		 * this guard a later msgrcv / msgctl(IPC_STAT) from the
		 * same child trips EACCES, defeating the point of fixing
		 * the coverage gap.
		 */
		static const unsigned short mode_dict[] = { 0600, 0644, 0666 };
		struct msqid_ds *ds;

		allocated_size = sizeof(struct msqid_ds);
		buf = zmalloc_tracked(allocated_size);
		ds = buf;
		ds->msg_perm.uid = getuid();
		ds->msg_perm.gid = getgid();
		ds->msg_perm.mode =
			mode_dict[rnd_modulo_u32(ARRAY_SIZE(mode_dict))] | 0400;
		input_buf = true;
		break;
	}
	default:
		/* IPC_STAT, MSG_STAT */
		allocated_size = sizeof(struct msqid_ds);
		buf = zmalloc_tracked(allocated_size);
		break;
	}

	rec->a3 = (unsigned long) buf;

	ipcctl_post_state_alloc(rec, buf, allocated_size);

	/*
	 * IPC_SET is the only input branch: the kernel reads msg_perm
	 * from the buffer.  Relocate copy-preserving so the curated
	 * uid/gid/mode survive the move into the writable pool; without
	 * it the kernel reads pool zeros and EINVALs/EPERMs the call,
	 * silently neutering IPC_SET coverage.  IPC_INFO / MSG_INFO /
	 * IPC_STAT / MSG_STAT are pure outputs -- the kernel writes
	 * them, so the cheaper relocate-only suffices.
	 */
	if (input_buf)
		avoid_shared_buffer_inout(&rec->a3, allocated_size);
	else
		avoid_shared_buffer_out(&rec->a3, allocated_size);
}

static void post_msgctl(struct syscallrecord *rec)
{
	post_ipcctl_buf_free(rec, "post_msgctl");
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
