/*
 * SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
 *                          const char __user *, uargs)
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/filter.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define SECCOMP_SET_MODE_STRICT		0
#define SECCOMP_SET_MODE_FILTER		1
#define SECCOMP_GET_ACTION_AVAIL	2
#define SECCOMP_GET_NOTIF_SIZES		3

#define SECCOMP_FILTER_FLAG_TSYNC		(1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG			(1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW		(1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH		(1UL << 4)
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV	(1UL << 5)

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS	0x80000000U
#endif
#ifndef SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_KILL_THREAD		0x00000000U
#endif
#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP		0x00030000U
#endif
#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO		0x00050000U
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF		0x7fc00000U
#endif
#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE		0x7ff00000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG			0x7ffc0000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW		0x7fff0000U
#endif

static const uint32_t seccomp_ret_actions[] = {
	SECCOMP_RET_KILL_PROCESS,
	SECCOMP_RET_KILL_THREAD,
	SECCOMP_RET_TRAP,
	SECCOMP_RET_ERRNO,
	SECCOMP_RET_USER_NOTIF,
	SECCOMP_RET_TRACE,
	SECCOMP_RET_LOG,
	SECCOMP_RET_ALLOW,
};

/*
 * Snapshot of the dispatch op and the per-op heap pointer the post
 * handler reads, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so the post path is immune to a sibling syscall scribbling
 * rec->a1 (op) or rec->a3 (heap pointer) between the syscall returning
 * and the post handler running.  The old post handler dispatched off
 * rec->a1 directly: a flip from SECCOMP_GET_ACTION_AVAIL or
 * SECCOMP_GET_NOTIF_SIZES into SECCOMP_SET_MODE_FILTER would deref the
 * smaller allocation as a sock_fprog and reach a wild fprog->filter
 * free; a flip away from SECCOMP_SET_MODE_FILTER would leak the
 * sock_fprog and its filter.
 *
 * Per-op allocation matrix.  Of the four SECCOMP_* ops, three allocate
 * a heap buffer that the post handler has to free:
 *
 *   SECCOMP_SET_MODE_FILTER  -> struct sock_fprog *
 *   SECCOMP_GET_ACTION_AVAIL -> uint32_t *
 *   SECCOMP_GET_NOTIF_SIZES  -> seccomp_notif_sizes-sized buffer
 *
 * SECCOMP_SET_MODE_STRICT does not allocate; sanitise leaves
 * post_state NULL and the post handler returns early on snap == NULL.
 *
 * Note: for SECCOMP_SET_MODE_FILTER the post handler also reads
 * rec->a2 to decide whether SECCOMP_FILTER_FLAG_NEW_LISTENER set the
 * listener-fd return.  That flag word is a separate scribble vector
 * from the opcode and is left to a future change -- the worst-case
 * outcome of a flag scribble there is a wrongly-classified retval (an
 * extra close() of a non-fd or a missed close() of a real listener
 * fd), not a UAF.
 */
struct seccomp_post_state {
	unsigned int op;
	void *heap;
};

static void sanitise_seccomp(struct syscallrecord *rec)
{
	struct seccomp_post_state *snap;
	void *heap = NULL;

	rec->post_state = 0;

	if (rec->a1 == SECCOMP_SET_MODE_STRICT) {
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}

	if (rec->a1 == SECCOMP_SET_MODE_FILTER) {
		/*
		 * FILTER mode needs uargs pointing to a valid struct sock_fprog
		 * containing a BPF program.  Use bpf_gen_seccomp() which builds
		 * seccomp-flavoured cBPF programs with the Markov chain generator.
		 */
#ifdef USE_BPF
		unsigned long *addr = NULL;
		unsigned long len = 0;

		bpf_gen_seccomp(&addr, &len);
		rec->a3 = (unsigned long) addr;
		heap = addr;
#endif
	}

	if (rec->a1 == SECCOMP_GET_ACTION_AVAIL) {
		/*
		 * uargs must point to a uint32_t containing the action to probe.
		 * Pick a random valid SECCOMP_RET_* action.
		 */
		uint32_t *action = zmalloc(sizeof(*action));

		*action = seccomp_ret_actions[rand() % ARRAY_SIZE(seccomp_ret_actions)];
		rec->a2 = 0;
		rec->a3 = (unsigned long) action;
		heap = action;
	}

	if (rec->a1 == SECCOMP_GET_NOTIF_SIZES) {
		/*
		 * uargs must point to a writable struct seccomp_notif_sizes
		 * (3 x __u16) for the kernel to fill in.
		 */
		void *sizes = zmalloc(3 * sizeof(uint16_t));

		rec->a2 = 0;
		rec->a3 = (unsigned long) sizes;
		heap = sizes;
	}

	/*
	 * Snapshot the op alongside the heap pointer.  rec->a1 (op) and
	 * rec->a3 (heap) are both ABI-exposed; the old post handler
	 * dispatched off rec->a1 directly and a sibling scribble would
	 * either leak the sock_fprog or coerce the smaller GET_*
	 * allocation into being treated as one.
	 */
	if (heap != NULL) {
		snap = zmalloc(sizeof(*snap));
		snap->op = rec->a1;
		snap->heap = heap;
		rec->post_state = (unsigned long) snap;
	}
}

static void post_seccomp(struct syscallrecord *rec)
{
	struct seccomp_post_state *snap = (struct seccomp_post_state *) rec->post_state;

	rec->a3 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_seccomp: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: if something corrupted the snapshot itself,
	 * the inner heap pointer may no longer reference our allocation.
	 * snap is only allocated when a heap pointer was paired with it,
	 * so a NULL here is itself corruption -- the < 0x10000 band of
	 * looks_like_corrupted_ptr() catches it without a separate guard.
	 */
	if (looks_like_corrupted_ptr(rec, snap->heap)) {
		outputerr("post_seccomp: rejected suspicious snap heap=%p (post_state-scribbled?)\n",
			  snap->heap);
		deferred_freeptr(&rec->post_state);
		return;
	}

	switch (snap->op) {
#ifdef USE_BPF
	case SECCOMP_SET_MODE_FILTER: {
		struct sock_fprog *fprog = (struct sock_fprog *) snap->heap;

		if (rec->a2 & SECCOMP_FILTER_FLAG_NEW_LISTENER) {
			int fd = (int)rec->retval;

			if (fd >= 0 && fd < (1 << 20)) {
				close(fd);
			} else if (fd >= 0) {
				outputerr("post_seccomp: rejecting out-of-bound NEW_LISTENER fd=%d\n", fd);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
		}

		free(fprog->filter);
		deferred_free_enqueue(fprog, NULL);
		break;
	}
#endif
	case SECCOMP_GET_ACTION_AVAIL:
	case SECCOMP_GET_NOTIF_SIZES:
		deferred_free_enqueue(snap->heap, NULL);
		break;
	}

	deferred_freeptr(&rec->post_state);
}

static unsigned long seccomp_ops[] = {
	SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER,
	SECCOMP_GET_ACTION_AVAIL, SECCOMP_GET_NOTIF_SIZES,
};

static unsigned long seccomp_flags[] = {
	SECCOMP_FILTER_FLAG_TSYNC,
	SECCOMP_FILTER_FLAG_LOG,
	SECCOMP_FILTER_FLAG_SPEC_ALLOW,
	SECCOMP_FILTER_FLAG_NEW_LISTENER,
	SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
	SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
};

struct syscallentry syscall_seccomp = {
	.name = "seccomp",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST, [2] = ARG_ADDRESS },
	.argname = { [0] = "op", [1] = "flags", [2] = "uargs" },
	.arg_params[0].list = ARGLIST(seccomp_ops),
	.arg_params[1].list = ARGLIST(seccomp_flags),
	.sanitise = sanitise_seccomp,
	.post = post_seccomp,
	.group = GROUP_PROCESS,
};
