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
#include "rnd.h"
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
 * from the opcode and is snapshotted via the arg_shadow mechanism
 * (entry->arg_snapshot_mask + get_arg_snapshot()) rather than this
 * post_state slot, since the handler only consumes a single flag
 * bit rather than a paired allocation pointer.
 */
#define SECCOMP_POST_STATE_MAGIC	0x534543434F4D505FUL	/* "SECCOMP_" */
struct seccomp_post_state {
	unsigned long magic;
	unsigned int op;
	void *heap;
};

/*
 * Stratified op picker.  Uniform sampling across the four SECCOMP ops
 * spends a quarter of the budget on SECCOMP_SET_MODE_STRICT, which
 * irreversibly seccomps the child and shuts down further coverage of
 * this syscall in that task.  Bias the picker toward SET_MODE_FILTER
 * (the BPF install path is where the interesting program-load and
 * listener-fd logic lives) and away from STRICT, while still hitting
 * GET_ACTION_AVAIL and GET_NOTIF_SIZES regularly.
 *
 *   60%  SECCOMP_SET_MODE_FILTER
 *   20%  SECCOMP_GET_ACTION_AVAIL
 *   10%  SECCOMP_GET_NOTIF_SIZES
 *   10%  SECCOMP_SET_MODE_STRICT
 */
static unsigned int pick_seccomp_op(void)
{
	unsigned int r = rnd_modulo_u32(100);

	if (r < 60)
		return SECCOMP_SET_MODE_FILTER;
	if (r < 80)
		return SECCOMP_GET_ACTION_AVAIL;
	if (r < 90)
		return SECCOMP_GET_NOTIF_SIZES;
	return SECCOMP_SET_MODE_STRICT;
}

static void sanitise_seccomp(struct syscallrecord *rec)
{
	struct seccomp_post_state *snap;
	void *heap = NULL;

	rec->a1 = pick_seccomp_op();

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
		uint32_t *action = zmalloc_tracked(sizeof(*action));

		*action = seccomp_ret_actions[rnd_modulo_u32(ARRAY_SIZE(seccomp_ret_actions))];
		rec->a2 = 0;
		rec->a3 = (unsigned long) action;
		heap = action;
	}

	if (rec->a1 == SECCOMP_GET_NOTIF_SIZES) {
		/*
		 * uargs must point to a writable struct seccomp_notif_sizes
		 * (3 x __u16) for the kernel to fill in.
		 */
		void *sizes = zmalloc_tracked(3 * sizeof(uint16_t));

		rec->a2 = 0;
		rec->a3 = (unsigned long) sizes;
		heap = sizes;
	}

	/*
	 * Snapshot the op alongside the heap pointer (magic-cookie /
	 * private post_state: see post_state_register()).  Specific
	 * seccomp failure: the old post handler dispatched off rec->a1
	 * directly, so a sibling scribble would either leak the sock_fprog
	 * or coerce the smaller GET_* allocation into being treated as one.
	 */
	if (heap != NULL) {
		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic = SECCOMP_POST_STATE_MAGIC;
		snap->op = rec->a1;
		snap->heap = heap;
		rec->post_state = (unsigned long) snap;
		post_state_register(snap);
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
	 * Ownership-table check before any deref of snap.  The shape gate
	 * above is size-blind: a sibling scribble that redirects
	 * rec->post_state at a smaller foreign heap chunk (e.g. another
	 * syscall's own post_state snap, or any aligned heap allocation)
	 * still passes looks_like_corrupted_ptr().  Reading snap->magic
	 * out of a chunk shorter than sizeof(struct seccomp_post_state)
	 * is a heap-buffer-overflow under ASAN, and the magic-cookie
	 * filter that follows would happily accept any chunk whose first
	 * eight bytes happen to collide with SECCOMP_POST_STATE_MAGIC
	 * (a stale same-type snapshot still resident on the deferred-free
	 * ring is the obvious collision source).  Gate on the ownership
	 * table -- which is a pure pointer comparison and well-defined
	 * regardless of the underlying allocation size -- so foreign
	 * pointers never reach the magic check or the inner-field reads.
	 * On a miss the snap was never one we produced, so there is
	 * nothing for this handler to unregister or free.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_seccomp: rejected post_state=%p not in ownership "
			  "table (post_state-redirected to foreign allocation?)\n",
			  snap);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * seccomp_post_state.  A cookie mismatch means snap does not
	 * point at our struct -- abandon without freeing rather than
	 * dispatch on a wild op or hand snap->heap to free().
	 */
	if (snap->magic != SECCOMP_POST_STATE_MAGIC) {
		outputerr("post_seccomp: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
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
		post_state_unregister(snap);
		deferred_freeptr(&rec->post_state);
		return;
	}

	switch (snap->op) {
#ifdef USE_BPF
	case SECCOMP_SET_MODE_FILTER: {
		struct sock_fprog *fprog = (struct sock_fprog *) snap->heap;

		if (get_arg_snapshot(rec, 2) & SECCOMP_FILTER_FLAG_NEW_LISTENER) {
			int fd = (int)rec->retval;

			if (fd >= 0 && fd < (1 << 20)) {
				close(fd);
			} else if (fd >= 0) {
				outputerr("post_seccomp: rejecting out-of-bound NEW_LISTENER fd=%d\n", fd);
				post_handler_corrupt_ptr_bump(rec, NULL);
			}
		}

		/*
		 * Wrapper-side gate before reading fprog->filter:
		 * looks_like_corrupted_ptr() above is shape-only (heap-band
		 * + alignment), so a heap-shaped but unmapped snap->heap
		 * would survive and fault on the inner-pointer read here.
		 * Require the wrapper to be a tracked allocation (one we
		 * produced via bpf_gen_seccomp) or readable for a sock_fprog-
		 * sized window.  When neither holds, skip the inner-free
		 * dispatch; the outer wrapper still enqueues so the
		 * post_state slot is released.  Mirrors the bpf_free_filter()
		 * inner-filter gate.
		 *
		 * Inner-filter free is alloc_track_lookup()-gated and routed
		 * through deferred_free_enqueue() rather than a shape-only
		 * gate + direct free().  A scribbled fprog->filter that
		 * aliases a chunk admitted to the deferred ring by another
		 * site passes any shape check (the alias is a valid aligned
		 * heap address) but misses the ownership check -- ring
		 * admission drained the chunk from alloc_track -- so the
		 * inner free is skipped.  A shape-only gate would have landed
		 * an out-of-band free on the ring-pinned chunk, and the
		 * original site's later ring_evict_oldest_safe would surface
		 * as an ASAN bad-free.  Mirrors bpf_free_filter() and
		 * syscalls/bpf.c BPF_PROG_LOAD eBPF cleanup.
		 */
		if (alloc_track_lookup(fprog) ||
		    range_readable_user(fprog, sizeof(struct sock_fprog))) {
			if (fprog->filter != NULL &&
			    alloc_track_lookup(fprog->filter))
				deferred_free_enqueue(fprog->filter);
		}
		deferred_free_enqueue(fprog);
		break;
	}
#endif
	case SECCOMP_GET_ACTION_AVAIL:
	case SECCOMP_GET_NOTIF_SIZES:
		deferred_free_enqueue(snap->heap);
		break;
	}

	post_state_unregister(snap);
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
	/* a2 (flags word) is read by post_seccomp to decide whether
	 * SECCOMP_FILTER_FLAG_NEW_LISTENER caused the syscall to return a
	 * listener fd that the handler must close.  Shadow it so a sibling
	 * stomp of rec->a2 between dispatch and post bumps
	 * arg_shadow_stomp from inside get_arg_snapshot() and the handler
	 * still classifies retval against the flags the kernel actually
	 * saw, instead of either leaking a real listener fd (stomp clears
	 * the bit) or close()ing a non-fd return value (stomp sets it). */
	.arg_snapshot_mask = (1u << 1),
};
