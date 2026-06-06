/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "deferred-free.h"
#include "objects.h"
#include "pids.h"
#include "publish_resource.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * OBJ_AIO_CTX pool: producer-side cache of live aio_context_t handles
 * returned by io_setup via its user out-pointer.  Consumed by io_submit/
 * io_getevents/io_pgetevents/io_destroy/io_cancel argument generation
 * so subsequent fuzzed calls hit contexts the kernel actually has on
 * hand instead of dead-on-arrival random integers.  Lives in the
 * per-child OBJ_LOCAL pool; the pool destructor calls real io_destroy()
 * on shutdown so produced contexts (each a kernel slab + ring mmap)
 * don't leak past child lifetime.
 */
static void aio_ctx_destructor(struct object *obj)
{
	syscall(SYS_io_destroy, obj->aioobj.ctx);
}

static void init_aio_ctx_pool(void)
{
	struct objhead *head;

	head = get_objhead(OBJ_GLOBAL, OBJ_AIO_CTX);
	if (head == NULL)
		return;

	/* Wire the destructor on the OBJ_GLOBAL head; child OBJ_LOCAL
	 * pools inherit it from here at child fork time
	 * (init_object_lists() copies destroy/dump from the GLOBAL head). */
	head->destroy = &aio_ctx_destructor;
}

REG_GLOBAL_OBJ(aio_ctx, init_aio_ctx_pool);

void register_aio_ctx(unsigned long ctx)
{
	if (ctx == 0)
		return;

	publish_resource(OBJ_AIO_CTX, ctx, NULL);
}

unsigned long get_random_aio_ctx(void)
{
	struct object *obj;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_AIO_CTX) == true)
		return 0;

	obj = get_random_object(OBJ_AIO_CTX, OBJ_LOCAL);
	if (obj == NULL)
		return 0;
	return obj->aioobj.ctx;
}

/*
 * Snapshot for the post handler.  Mirrors the pipe/socketpair shape:
 *
 *   1. The snap struct carries a magic cookie that the post handler
 *      checks before dereferencing snap->ctxp.  A sibling scribble of
 *      rec->post_state with a heap-shaped pointer to a foreign chunk
 *      survives looks_like_corrupted_ptr() but fails the cookie gate.
 *
 *   2. The snap pointer is registered in the post-state ownership
 *      table at sanitise time and checked in the post handler via
 *      post_state_is_owned().  A cookie-collision foreign chunk would
 *      otherwise sail past the magic check.
 *
 *   3. snap->ctxp records the out-pointer value as written into rec->a2
 *      at sanitise time.  The post handler compares snap->ctxp against
 *      the live rec->a2 and bails on mismatch -- a sibling scribble of
 *      rec->a2 between sanitise and post means the kernel either wrote
 *      to a different buffer (so *snap->ctxp is the pre-syscall zero
 *      we stamped) or rec->a2 was clobbered after the syscall returned
 *      (so *snap->ctxp may have been written-to-then-unmapped under
 *      us).  Either way the aio_context_t we'd read is untrustworthy.
 */
#define IO_SETUP_POST_STATE_MAGIC	0x494F5354505F4D47UL	/* "IOSTP_MG" */
struct io_setup_post_state {
	unsigned long magic;
	unsigned long *ctxp;
};

static void sanitise_io_setup(struct syscallrecord *rec)
{
	unsigned long *ctxp;
	struct io_setup_post_state *snap;

	/* ctxp must point to a zero-initialized aio_context_t */
	ctxp = (unsigned long *) get_writable_address(sizeof(*ctxp));
	if (ctxp == NULL)
		return;
	*ctxp = 0;
	rec->a2 = (unsigned long) ctxp;

	/* Re-route ctxp out of any alloc_shared / libc-heap region. */
	avoid_shared_buffer_out(&rec->a2, sizeof(aio_context_t));

	/*
	 * Snapshot the user out-pointer for the post handler.  Sibling
	 * syscalls in the child can scribble rec->aN between sanitise and
	 * post; reading from a private slot keeps the deref pointed at the
	 * buffer the kernel actually wrote into, and the identity check in
	 * the post handler turns a scribbled rec->a2 into a clean bail
	 * rather than a quiet read from a stale or unmapped address.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = IO_SETUP_POST_STATE_MAGIC;
	snap->ctxp = (unsigned long *) rec->a2;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

/*
 * Post-derived secondary-object registrar wired via
 * .ret_objtype_via_post.  io_setup allocates a kernel ioctx_t (slab
 * + per-context ring mmap) and writes the resulting aio_context_t
 * out to *ctxp.  Hand the freshly-minted context to the OBJ_AIO_CTX
 * pool so io_submit/io_getevents/io_pgetevents/io_destroy/io_cancel
 * consumers can pick it up; the per-child pool destructor issues
 * the real io_destroy() at child teardown so produced contexts
 * don't outlive the producing child.  Runs ahead of post_io_setup(),
 * which clears rec->post_state during cleanup.  Does its own shape
 * + magic + ownership + inner-pointer-identity validation before
 * deref so a sibling-stomped post_state doesn't drive
 * register_aio_ctx() with foreign bytes -- corruption attribution
 * stays in post_io_setup() below, which repeats the same checks and
 * owns the inner-ptr-mismatch counter bump.
 */
static void post_io_setup_record_ctx(struct syscallrecord *rec)
{
	struct io_setup_post_state *snap =
		(struct io_setup_post_state *) rec->post_state;
	unsigned long *ctxp;
	unsigned long ctx;

	if ((long) rec->retval != 0)
		return;

	if (snap == NULL || looks_like_corrupted_ptr(rec, snap))
		return;

	if (!post_state_is_owned(snap))
		return;

	if (snap->magic != IO_SETUP_POST_STATE_MAGIC)
		return;

	/*
	 * Inner-pointer-identity check: snap->ctxp is the out-pointer
	 * captured at sanitise; rec->a2 is the live slot.  A mismatch
	 * means a sibling scribble retargeted the kernel's write or
	 * clobbered rec->a2 after return -- *snap->ctxp would read the
	 * pre-syscall zero we stamped (or unmapped bytes) either way.
	 */
	if ((unsigned long *) rec->a2 != snap->ctxp)
		return;

	ctxp = snap->ctxp;
	if (ctxp == NULL || looks_like_corrupted_ptr(rec, ctxp))
		return;

	/*
	 * The snapshot above protects the OUT-pointer (ctxp) from rec->aN
	 * scribbles, but the kernel-written aio_context_t value at *ctxp
	 * lives in the user-supplied buffer and is fair game for a sibling
	 * syscall to clobber between the syscall returning and this handler
	 * running.  A scribbled value handed to io_destroy() (called from
	 * the pool destructor) would make the kernel walk a foreign id
	 * through the per-mm aio context table.  aio_context_t is opaque,
	 * but a real kernel-allocated context is never zero — drop
	 * zero-valued reads instead of feeding them to the pool.
	 * Corruption-bump attribution stays in post_io_setup() so a
	 * single bad call is logged once.
	 */
	ctx = *ctxp;
	if (ctx == 0)
		return;

	register_aio_ctx(ctx);
}

/*
 * Cleanup-only sibling of post_io_setup_record_ctx().  Owns the
 * scratch-slot teardown, the zero-ctx corruption-bump, and the
 * inner-ptr-mismatch counter so the registrar above can stay focused
 * on adding ctxs to the pool.
 */
static void post_io_setup(struct syscallrecord *rec)
{
	struct io_setup_post_state *snap =
		(struct io_setup_post_state *) rec->post_state;
	unsigned long *ctxp;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_io_setup: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	if (!post_state_is_owned(snap)) {
		outputerr("post_io_setup: rejected post_state=%p not in "
			  "ownership table (post_state-redirected?)\n", snap);
		rec->post_state = 0;
		return;
	}

	if (snap->magic != IO_SETUP_POST_STATE_MAGIC) {
		outputerr("post_io_setup: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	if ((long) rec->retval != 0)
		goto out_free;

	/*
	 * Inner-pointer-identity check: snap->ctxp is the out-pointer
	 * captured at sanitise; rec->a2 is the live slot.  A mismatch
	 * means a sibling scribble retargeted the kernel's write or
	 * clobbered rec->a2 after return.  Bump the dedicated mismatch
	 * counter and skip the *ctxp deref entirely -- the
	 * aio_context_t there is untrustworthy.
	 */
	if ((unsigned long *) rec->a2 != snap->ctxp) {
		outputerr("post_io_setup: inner-ptr mismatch snap->ctxp=%p rec->a2=%p "
			  "(sibling-scribbled out-pointer)\n",
			  (void *) snap->ctxp, (void *) rec->a2);
		__atomic_add_fetch(&shm->stats.io_setup_inner_ptr_mismatch,
				   1, __ATOMIC_RELAXED);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	ctxp = snap->ctxp;
	if (ctxp == NULL || looks_like_corrupted_ptr(rec, ctxp))
		goto out_free;

	if (*ctxp == 0) {
		outputerr("post_io_setup: rejected zero ctx (kernel-write-buffer-scribbled?)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

out_free:
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
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
	.ret_objtype_via_post = post_io_setup_record_ctx,
	.rettype = RET_ZERO_SUCCESS,
};
