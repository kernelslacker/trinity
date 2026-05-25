/*
 * SYSCALL_DEFINE3(msgctl, int, msqid, int, cmd, struct msqid_ds __user *, buf)
 */
#include <stddef.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long msgctl_cmds[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	MSG_INFO, MSG_STAT,
};

/*
 * Mirrors the shmctl post_state shape -- msgctl shares the dense small-
 * chunk profile (struct msginfo / msqid_ds both fall in the same heap
 * size class as the shmctl buffers) and the same sibling-stomp exposure
 * on rec->post_state.  Hardening msgctl now rather than after the first
 * fault is consistent with the shmctl fix and avoids leaving the two
 * paths to drift apart.
 *
 * The snap wraps the inner IPC buffer pointer with a magic cookie and
 * registers itself in the post-state ownership table at allocation
 * time.  The post handler gates on three independent checks
 * (heap-shape, magic, ownership) before any free fires; on accept the
 * inner buffer is released through deferred_freeptr() first, then the
 * snap is unregistered and itself routed through deferred-free.  On any
 * reject the allocations leak rather than fault.
 */
#define MSGCTL_POST_STATE_MAGIC	0x4D5347434C5F4D47UL	/* "MSGCL_MG" */
struct msgctl_post_state {
	unsigned long magic;
	unsigned long buf;
	size_t buf_size;
};

static void sanitise_msgctl(struct syscallrecord *rec)
{
	struct msgctl_post_state *snap;
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
		break;
	}
	default:
		/* IPC_STAT, MSG_STAT */
		allocated_size = sizeof(struct msqid_ds);
		buf = zmalloc_tracked(allocated_size);
		break;
	}

	rec->a3 = (unsigned long) buf;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = MSGCTL_POST_STATE_MAGIC;
	snap->buf      = (unsigned long) buf;
	snap->buf_size = allocated_size;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);

	avoid_shared_buffer_out(&rec->a3, allocated_size);
}

static void post_msgctl(struct syscallrecord *rec)
{
	struct msgctl_post_state *snap =
		(struct msgctl_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_msgctl: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * msgctl_post_state.  Bail without freeing on mismatch.
	 */
	if (snap->magic != MSGCTL_POST_STATE_MAGIC) {
		outputerr("post_msgctl: rejected snap with bad magic 0x%lx at %p "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic, snap);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Shape + magic passed, but a foreign chunk could in principle
	 * carry the matching cookie by coincidence (e.g. another in-flight
	 * msgctl child's snap).  Verify against the ownership table so
	 * only snaps we registered at sanitise time can reach free().
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_msgctl: rejected post_state=%p (buf_size=%zu) "
			  "not in ownership table (post_state-redirected?)\n",
			  snap, snap->buf_size);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a3 = 0;
	deferred_freeptr(&snap->buf);
	post_state_unregister(snap);
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
