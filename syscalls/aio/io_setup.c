/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "deferred-free.h"
#include "objects.h"
#include "output-poison.h"
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
 * Sanitise-time fallback called from io_submit/io_getevents/io_pgetevents
 * sanitisers when the OBJ_AIO_CTX pool is empty (no io_setup has landed
 * yet in this child).  Calls the real io_setup(2) directly to mint one
 * fresh aio_context_t, registers it in the per-child pool so the per-child
 * destructor will real-io_destroy() it on shutdown, and returns the new
 * ctx for the caller to use as rec->a1.  Without this, every io_submit /
 * io_getevents / io_pgetevents call before the fuzzer happens to pick
 * io_setup gets ctx=0 (or, 1/8 of the time, a raw rand64) and short-
 * circuits with -EINVAL inside the kernel's lookup_ioctx() -- never
 * reaching the kernel's iocb import path or the per-ring event-queue
 * drain path the syscall is supposed to exercise.
 */
unsigned long seed_aio_ctx_if_empty(void)
{
	aio_context_t ctx = 0;

	if (objects_pool_empty(OBJ_LOCAL, OBJ_AIO_CTX) == false)
		return get_random_aio_ctx();

	if (syscall(SYS_io_setup, 32, &ctx) != 0)
		return 0;
	if (ctx == 0)
		return 0;

	register_aio_ctx((unsigned long) ctx);
	return (unsigned long) ctx;
}

/*
 * Snapshot for the post handler.  Mirrors the pipe/socketpair shape:
 *
 *   1. The snap struct carries a magic cookie that the post handler
 *      checks before dereferencing *get_arg_snapshot(rec, 2).  A
 *      sibling scribble of rec->post_state with a heap-shaped pointer
 *      to a foreign chunk survives looks_like_corrupted_ptr() but
 *      fails the cookie gate.
 *
 *   2. The snap pointer is registered in the post-state ownership
 *      table at sanitise time and checked in the post handler via
 *      post_state_is_owned().  A cookie-collision foreign chunk would
 *      otherwise sail past the magic check.
 *
 * The OUT-pointer (a2 / ctxp) defence is now generic:
 * .arg_snapshot_mask opts a2 into the dispatch-time arg_shadow capture
 * (snapshotted inside __do_syscall() after the final
 * blanket_address_scrub, from the locals about to enter the kernel),
 * and the post handler reads it via get_arg_snapshot(rec, 2).  A
 * sibling scribble of rec->a2 between dispatch and post bumps the
 * generic arg_shadow_stomp tripwire from inside the accessor; the
 * returned value is the kernel-visible address, so the *ctxp deref
 * still hits the buffer the kernel actually wrote.
 */
#define IO_SETUP_POST_STATE_MAGIC	0x494F5354505F4D47UL	/* "IOSTP_MG" */
struct io_setup_post_state {
	unsigned long magic;
	/*
	 * Seed for the poison pattern stamped into the aio_context_t
	 * OUT-buffer (*ctxp) at sanitise time.  Fed back into
	 * check_output_struct() on the retval == 0 success arm of
	 * post_io_setup_record_ctx(): a byte-identical 8-byte poison after
	 * success means the kernel returned 0 without writing the
	 * aio_context_t at all.  Snapshot lives in rec->post_state so a
	 * sibling stomp of rec->aN between dispatch and post cannot
	 * redirect the poison check at an unrelated heap page whose
	 * residual bytes happen to match some earlier seed.  A seed of 0
	 * means sanitise chose not to stamp (unwritable pointer) -- the
	 * post handler no-ops the poison check rather than confuse "we
	 * could not poison" with "kernel did not write".
	 */
	uint64_t poison_seed;
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
	avoid_shared_buffer_inout(&rec->a2, sizeof(aio_context_t));

	/* magic-cookie / private post_state: see post_state_register().
	 * The OUT-pointer is defended via .arg_snapshot_mask + the
	 * dispatch-time arg_shadow capture, not a snap field. */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = IO_SETUP_POST_STATE_MAGIC;
	snap->poison_seed = 0;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);

	/*
	 * Stamp a per-call poison pattern into the aio_context_t OUT-buffer
	 * the kernel is about to fill.  The post handler feeds the seed
	 * back into check_output_struct(); a byte-identical poison after a
	 * retval == 0 return means the kernel returned success without
	 * calling copy_to_user() -- io_setup(2) is contracted to write the
	 * fresh aio_context_t on success.  Gate on range_readable_user()
	 * so a writable-pool draw that avoid_shared_buffer_inout() moved
	 * to an address that is no longer provably mapped -- e.g. a
	 * sibling munmap between allocation and now -- does not SIGSEGV
	 * the sanitiser inside poison_output_struct's byte-walk.  On skip
	 * the seed stays 0 and the post handler no-ops the poison check
	 * while the existing zero-ctx bookkeeping keeps running.  Done
	 * after avoid_shared_buffer_inout() so the poison lands on the
	 * final buffer the kernel will see.
	 */
	{
		void *buf = (void *)(unsigned long) rec->a2;

		if (range_readable_user(buf, sizeof(aio_context_t)))
			snap->poison_seed = poison_output_struct(buf,
								 sizeof(aio_context_t),
								 0);
	}
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
 * + magic + ownership validation and reads the OUT-pointer via the
 * generic arg_shadow accessor before deref so a sibling-stomped
 * post_state or rec->a2 doesn't drive register_aio_ctx() with
 * foreign bytes -- corruption attribution for the snap-struct gates
 * stays in post_io_setup() below; out-pointer corruption is bumped
 * generically by arg_shadow_stomp from inside get_arg_snapshot().
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
	 * The OUT-pointer (a2 / ctxp) is read via the generic arg_shadow
	 * accessor: it returns the kernel-visible address snapshotted in
	 * __do_syscall() after the final blanket_address_scrub.  A
	 * sibling stomp of rec->a2 between dispatch and here bumps
	 * arg_shadow_stomp from inside the accessor and the post handler
	 * still sees the address the kernel actually wrote.
	 */
	ctxp = (unsigned long *) get_arg_snapshot(rec, 2);
	if (ctxp == NULL || looks_like_corrupted_ptr(rec, ctxp))
		return;

	/*
	 * Untouched-buffer poison check: retval == 0 but the aio_context_t
	 * OUT-buffer still byte-for-byte matches the poison pattern we
	 * stamped at sanitise time -- the kernel returned success without
	 * writing the aio_context_t.  Guarded on poison_seed so the
	 * unwritable-address "we couldn't poison" path is not confused with
	 * "kernel didn't write".  Runs on every success (no ONE_IN gate)
	 * because the check is an 8-byte compare with no re-issue.  The
	 * existing zero-ctx / arg_shadow / snap-magic corruption gates keep
	 * running in post_io_setup() and stay attribution-owning; this arm
	 * only bumps the shared post_handler_untouched_out_buf slot.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip(ctxp, sizeof(aio_context_t),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	/*
	 * arg_shadow protects the OUT-pointer (ctxp) from rec->aN scribbles,
	 * but the kernel-written aio_context_t value at *ctxp lives in the
	 * user-supplied buffer and is fair game for a sibling syscall to
	 * clobber between the syscall returning and this handler running.
	 * A scribbled value handed to io_destroy() (called from the pool
	 * destructor) would make the kernel walk a foreign id through the
	 * per-mm aio context table.  aio_context_t is opaque, but a real
	 * kernel-allocated context is never zero — drop zero-valued reads
	 * instead of feeding them to the pool.  Corruption-bump attribution
	 * stays in post_io_setup() so a single bad call is logged once.
	 */
	ctx = *ctxp;
	if (ctx == 0)
		return;

	register_aio_ctx(ctx);
}

/*
 * Cleanup-only sibling of post_io_setup_record_ctx().  Owns the
 * scratch-slot teardown and the zero-ctx corruption-bump so the
 * registrar above can stay focused on adding ctxs to the pool.
 * Reads the OUT-pointer via the generic arg_shadow accessor; a
 * sibling scribble of rec->a2 between dispatch and here bumps
 * arg_shadow_stomp from inside the accessor.
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
	 * Read the OUT-pointer via the generic arg_shadow accessor: it
	 * returns the kernel-visible address captured in __do_syscall() and
	 * bumps arg_shadow_stomp from inside the accessor on any
	 * post-dispatch sibling scribble of rec->a2, so a separate
	 * per-syscall mismatch counter would only ever fire on the same
	 * stomp class the generic tripwire already covers.
	 */
	ctxp = (unsigned long *) get_arg_snapshot(rec, 2);
	if (ctxp == NULL || looks_like_corrupted_ptr(rec, ctxp))
		goto out_free;

	if (*ctxp == 0) {
		outputerr("post_io_setup: rejected zero ctx (kernel-write-buffer-scribbled?)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_io_setup = {
	.name = "io_setup",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "nr_events", [1] = "ctxp" },
	.arg_params[0].range.low = 1,
	.arg_params[0].range.hi = 256,
	.group = GROUP_VFS,
	.sanitise = sanitise_io_setup,
	.post = post_io_setup,
	.ret_objtype_via_post = post_io_setup_record_ctx,
	.rettype = RET_ZERO_SUCCESS,
	/* a2 (ctxp) is the kernel's OUT-pointer; both post handlers
	 * deref through it.  Shadow it so a sibling stomp between
	 * dispatch and post bumps arg_shadow_stomp from inside
	 * get_arg_snapshot() and the handlers still see the address the
	 * kernel actually wrote, not the stomped value. */
	.arg_snapshot_mask = (1u << 1),
};
