/*
 * SYSCALL_DEFINE3(msgctl, int, msqid, int, cmd, struct msqid_ds __user *, buf)
 */
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include "ipc-common.h"
#include "output-poison.h"
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
	struct ipcctl_post_state *snap;
	void *buf;
	unsigned long allocated_size;

	rec->post_state = 0;

	switch (rec->a2) {
	case IPC_RMID:
		rec->a3 = 0;
		return;
	case IPC_INFO:
	case MSG_INFO:
		allocated_size = sizeof(struct msginfo);
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
		 * the coverage gap.  msg_qbytes becomes the queue's byte
		 * limit (IPC_SET_MSG_QBYTES).  The buffer comes from the
		 * call's pool, where the kernel reads it in place.
		 */
		static const unsigned short mode_dict[] = { 0600, 0644, 0666 };
		struct msqid_ds *ds = get_writable_struct(sizeof(*ds));

		rec->a3 = (unsigned long) ds;
		if (ds == NULL)
			return;
		memset(ds, 0, sizeof(*ds));
		ds->msg_perm.uid = getuid();
		ds->msg_perm.gid = getgid();
		ds->msg_perm.mode =
			mode_dict[rnd_modulo_u32(ARRAY_SIZE(mode_dict))] | 0400;
		ds->msg_qbytes = IPC_SET_MSG_QBYTES;
		return;
	}
	default:
		/* IPC_STAT, MSG_STAT */
		allocated_size = sizeof(struct msqid_ds);
		break;
	}

	/*
	 * The rest are pure outputs.  The buffer comes from the call's
	 * pool, which avoid_shared_buffer_out() would leave where it is,
	 * so the kernel writes the buffer the poison is stamped into, and
	 * the shared post handler re-reads it to catch a success return
	 * with no matching copy_to_user().
	 */
	buf = get_writable_struct(allocated_size);
	rec->a3 = (unsigned long) buf;
	if (buf == NULL)
		return;
	snap = ipcctl_post_state_alloc(rec, buf, allocated_size);
	snap->poison_seed = poison_output_struct(buf, allocated_size, 0);
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
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
};
