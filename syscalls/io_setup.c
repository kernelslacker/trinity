/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "objects.h"
#include "pids.h"
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
	struct object *obj;

	if (ctx == 0)
		return;

	obj = alloc_object();
	obj->aioobj.ctx = ctx;
	add_object(obj, OBJ_LOCAL, OBJ_AIO_CTX);
}

unsigned long get_random_aio_ctx(void)
{
	struct object *obj;

	if (objects_empty(OBJ_AIO_CTX) == true)
		return 0;

	obj = get_random_object(OBJ_AIO_CTX, OBJ_LOCAL);
	if (obj == NULL)
		return 0;
	return obj->aioobj.ctx;
}

static void sanitise_io_setup(struct syscallrecord *rec)
{
	unsigned long *ctxp;

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
	 * buffer the kernel actually wrote into.
	 */
	rec->post_state = rec->a2;
}

/*
 * io_setup allocates a kernel ioctx_t (slab + per-context ring mmap)
 * and writes the resulting aio_context_t out to *ctxp.  Hand the
 * freshly-minted context to the OBJ_AIO_CTX pool so io_submit/
 * io_getevents/io_pgetevents/io_destroy/io_cancel consumers can pick
 * it up; the per-child pool destructor issues the real io_destroy()
 * at child teardown so produced contexts don't outlive the producing
 * child.
 */
static void post_io_setup(struct syscallrecord *rec)
{
	unsigned long *ctxp;
	unsigned long ctx;

	if ((long) rec->retval != 0)
		return;

	ctxp = (unsigned long *) rec->post_state;
	if (looks_like_corrupted_ptr(rec, ctxp)) {
		rec->post_state = 0;
		return;
	}

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
	 */
	ctx = *ctxp;
	if (ctx == 0) {
		outputerr("post_io_setup: rejected zero ctx (kernel-write-buffer-scribbled?)\n");
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	register_aio_ctx(ctx);
	rec->post_state = 0;
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
	.rettype = RET_ZERO_SUCCESS,
};
