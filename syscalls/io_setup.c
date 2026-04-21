/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "objects.h"
#include "pids.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_io_setup(struct syscallrecord *rec)
{
	unsigned long *ctxp;

	/* ctxp must point to a zero-initialized aio_context_t */
	ctxp = (unsigned long *) get_writable_address(sizeof(*ctxp));
	*ctxp = 0;
	rec->a2 = (unsigned long) ctxp;
}

static void post_io_setup(struct syscallrecord *rec)
{
	struct object *obj;
	unsigned long *ctxp;
	unsigned long ctx;

	if ((long) rec->retval != 0)
		return;

	ctxp = (unsigned long *) rec->a2;
	ctx = *ctxp;
	if (ctx == 0)
		return;

	obj = alloc_object();
	obj->aioobj.ctx = ctx;
	add_object(obj, OBJ_LOCAL, OBJ_AIO_CTX);
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
