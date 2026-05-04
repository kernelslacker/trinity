/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "deferred-free.h"
#include "objects.h"
#include "pids.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the io_setup input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the *ctxp dereference at a foreign
 * aio_context_t.  looks_like_corrupted_ptr() catches a non-heap value in
 * rec->a2 but cannot tell a real-but-wrong writable-arena address from
 * the original ctxp pointer, so a foreign-arena stomp slips past the
 * guard and the kernel's context id read lands in someone else's slot --
 * either fabricating a bogus AIO context registered with add_object() or
 * forging a spurious zero that silently drops a real context the kernel
 * just allocated.
 */
struct io_setup_post_state {
	unsigned long nr_events;
	unsigned long ctxp;
};

static void sanitise_io_setup(struct syscallrecord *rec)
{
	struct io_setup_post_state *snap;
	unsigned long *ctxp;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/* ctxp must point to a zero-initialized aio_context_t */
	ctxp = (unsigned long *) get_writable_address(sizeof(*ctxp));
	*ctxp = 0;
	rec->a2 = (unsigned long) ctxp;

	/*
	 * Snapshot the two input args the post oracle inspects.  Without
	 * this the post handler reads rec->a2 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong writable-arena address from the
	 * original ctxp pointer, so the *ctxp dereference would pull a
	 * context id out of a foreign allocation that the guard never
	 * inspected.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->nr_events = rec->a1;
	snap->ctxp      = rec->a2;
	rec->post_state = (unsigned long) snap;
}

static void post_io_setup(struct syscallrecord *rec)
{
	struct io_setup_post_state *snap =
		(struct io_setup_post_state *) rec->post_state;
	struct object *obj;
	unsigned long *ctxp;
	unsigned long ctx;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_io_setup: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if ((long) rec->retval != 0)
		goto out_free;

	ctxp = (unsigned long *) snap->ctxp;
	if (ctxp == NULL)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer field.  Reject
	 * a pid-scribbled ctxp before the *ctxp deref steers the context
	 * id read at a foreign allocation.
	 */
	if (looks_like_corrupted_ptr(rec, ctxp)) {
		outputerr("post_io_setup: rejected suspicious ctxp=%p (post_state-scribbled?)\n",
			  (void *) ctxp);
		goto out_free;
	}

	ctx = *ctxp;
	if (ctx == 0)
		goto out_free;

	obj = alloc_object();
	obj->aioobj.ctx = ctx;
	add_object(obj, OBJ_LOCAL, OBJ_AIO_CTX);

out_free:
	deferred_freeptr(&rec->post_state);
}

static void init_aio_global_ctx(void)
{
	struct object *obj;
	unsigned long ctx = 0;

	if (syscall(SYS_io_setup, 32, &ctx) != 0)
		return;

	obj = alloc_object();
	obj->aioobj.ctx = ctx;
	add_object(obj, OBJ_GLOBAL, OBJ_AIO_CTX);

	/* RELEASE store: pairs with the child-side ACQUIRE in get_random_aio_ctx(). */
	__atomic_store_n(&shm->aio_ctx_cached, ctx, __ATOMIC_RELEASE);

	output(0, "Reserved global AIO context 0x%lx.\n", ctx);
}

REG_GLOBAL_OBJ(aio_ctx, init_aio_global_ctx);

/*
 * Child path returns a single cached context: the AIO syscalls only need
 * *some* valid context for fuzzing — randomization across multiple contexts
 * adds little value here.  The ACQUIRE load pairs with the parent-side
 * RELEASE store in init_aio_global_ctx(), closing the same deadlock class
 * as the mapped_ring lockless pattern: a child crash mid-lock would leave
 * the parent stuck on objlock indefinitely.
 */
unsigned long get_random_aio_ctx(void)
{
	struct object *obj;

	if (getpid() != mainpid)
		return __atomic_load_n(&shm->aio_ctx_cached, __ATOMIC_ACQUIRE);

	if (objects_empty(OBJ_AIO_CTX) == true)
		return 0;

	obj = get_random_object(OBJ_AIO_CTX, OBJ_GLOBAL);
	if (obj == NULL)
		return 0;
	return obj->aioobj.ctx;
}

struct syscallentry syscall_io_setup = {
	.name = "io_setup",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "nr_events", [1] = "ctxp" },
	.arg_params[0].range.low = 1,
	.arg_params[0].range.hi = 256,
	.group = GROUP_VFS,
	.sanitise = sanitise_io_setup,
	.post = post_io_setup,
};
