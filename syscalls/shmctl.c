/*
 * SYSCALL_DEFINE3(shmctl, int, shmid, int, cmd, struct shmid_ds __user *, buf)
 */
#include <linux/ipc.h>
#include <linux/shm.h>
#include <stddef.h>
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long shmctl_ops[] = {
	IPC_STAT, IPC_SET, IPC_RMID, IPC_INFO,
	SHM_INFO, SHM_STAT, SHM_LOCK, SHM_UNLOCK,
};

/*
 * The IPC buffer handed to shmctl(IPC_STAT/IPC_INFO/SHM_INFO/SHM_STAT) is
 * the smallest tracked allocation in the fuzzer (sizeof(struct shminfo) = 20
 * bytes), so the heap arena is densely populated with adjacent 0x30-stride
 * slots.  When a sibling fuzz child's value-result syscall scribbles bytes
 * into another child's syscallrecord (which lives in shared memory) while
 * shmctl is in flight, rec->post_state (offset ~80) gets stomped with a
 * heap-shaped wild value often enough that the corrupted-ptr gate passes
 * roughly once per few thousand stomps -- and the resulting pointer flows
 * through to free(), faulting on a non-live slot.
 *
 * Wrap rec->post_state with a snap struct carrying a magic cookie and the
 * inner buffer pointer + size, then register the snap address in the
 * post-state ownership table at allocation time.  The post handler gates
 * on three independent checks before any free fires:
 *
 *   1. looks_like_corrupted_ptr() rejects a non-heap-shape snap pointer.
 *   2. snap->magic mismatch rejects a heap-shaped redirect to a foreign
 *      chunk that happens to be aligned and canonical but is not ours.
 *   3. post_state_is_owned() rejects the rare case where a foreign chunk
 *      passes the shape and magic checks by coincidence -- the ownership
 *      table records every snap we allocate, so a value not registered
 *      cannot be one we produced.
 *
 * On accept, the inner IPC buffer is released through deferred_freeptr()
 * first (so a freed inner pointer does not survive a snap-free abort),
 * then the snap is unregistered and itself routed through deferred-free.
 * On any reject, both allocations are leaked rather than fed to free() --
 * the leak is bounded by the per-cmd allocated_size cap and is the
 * canonical safe response to post-handler validation against in-flight
 * record corruption.
 */
#define SHMCTL_POST_STATE_MAGIC	0x53484D43544C5F4DUL	/* "SHMCTL_M" */
struct shmctl_post_state {
	unsigned long magic;
	unsigned long buf;
	size_t buf_size;
};

static void sanitise_shmctl(struct syscallrecord *rec)
{
	struct shmctl_post_state *snap;
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

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = SHMCTL_POST_STATE_MAGIC;
	snap->buf      = (unsigned long) buf;
	snap->buf_size = allocated_size;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);

	avoid_shared_buffer_out(&rec->a3, allocated_size);
}

static void post_shmctl(struct syscallrecord *rec)
{
	struct shmctl_post_state *snap =
		(struct shmctl_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_shmctl: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * shmctl_post_state.  A cookie mismatch means snap does not point
	 * at our struct -- bail without freeing, the pointer is suspect.
	 */
	if (snap->magic != SHMCTL_POST_STATE_MAGIC) {
		outputerr("post_shmctl: rejected snap with bad magic 0x%lx at %p "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic, snap);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Shape passed, magic matched, but a sibling-stomp can still
	 * redirect post_state to a different heap allocation that happens
	 * to be canonical, aligned, AND coincidentally carry the magic
	 * value in its first word (e.g. another shmctl child whose snap is
	 * still live).  Verify against the ownership table, which records
	 * every snap allocation at sanitise time; a value that fails the
	 * lookup cannot be one we produced.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_shmctl: rejected post_state=%p (buf_size=%zu) "
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
