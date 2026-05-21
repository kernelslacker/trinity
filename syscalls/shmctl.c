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
 * Wrap the IPC buffer in a header carrying a magic cookie so the post
 * handler can confirm the pointer it is about to free really came from
 * sanitise_shmctl().  A stomp that redirects post_state to a foreign
 * allocation will not match the cookie at that address and is rejected
 * before reaching deferred_freeptr().  The wrapper sits at the start of
 * the allocation, so freeing it releases the IPC buffer too.
 */
#define SHMCTL_BUF_MAGIC	0x53484D43544C4246UL	/* "SHMCTLBF" */
struct shmctl_buf_wrapper {
	unsigned long magic;
	/* user buffer (struct shminfo / shm_info / shmid_ds) starts here */
};

static void sanitise_shmctl(struct syscallrecord *rec)
{
	struct shmctl_buf_wrapper *w;
	void *buf = NULL;
	unsigned long allocated_size = 0;
	size_t total;

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

	total = sizeof(struct shmctl_buf_wrapper) + allocated_size;
	w = zmalloc_tracked(total);
	w->magic = SHMCTL_BUF_MAGIC;
	buf = (void *)(w + 1);

	rec->a3 = (unsigned long) buf;
	/* Snapshot for the post handler -- a3 may be scribbled by a sibling
	 * syscall before post_shmctl() runs.  post_state holds the wrapper
	 * (the tracked allocation start) so deferred_freeptr() can release
	 * it; the user buffer lives inside the same allocation. */
	rec->post_state = (unsigned long) w;

	avoid_shared_buffer_out(&rec->a3, allocated_size);
}

static void post_shmctl(struct syscallrecord *rec)
{
	struct shmctl_buf_wrapper *w = (struct shmctl_buf_wrapper *) rec->post_state;

	if (w == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, w)) {
		outputerr("post_shmctl: rejected suspicious wrapper=%p (pid-scribbled?)\n", w);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: w survived the heap-shape gate but a sibling
	 * scribble of rec->post_state with a heap-shaped pointer to a
	 * foreign allocation would let the wrong bytes pose as our wrapper.
	 * A cookie mismatch means w does not point at our allocation --
	 * bail without freeing, the pointer is suspect.
	 */
	if (w->magic != SHMCTL_BUF_MAGIC) {
		outputerr("post_shmctl: rejected wrapper with bad magic 0x%lx at %p "
			  "(post_state-stomped to foreign allocation?)\n",
			  w->magic, w);
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
	.argtype = { [0] = ARG_SYSV_SHM, [1] = ARG_OP, [2] = ARG_ADDRESS },
	.argname = { [0] = "shmid", [1] = "cmd", [2] = "buf" },
	.arg_params[1].list = ARGLIST(shmctl_ops),
	.sanitise = sanitise_shmctl,
	.post = post_shmctl,
};
