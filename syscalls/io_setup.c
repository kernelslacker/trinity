/*
 * SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
 */
#include <string.h>
#include "objects.h"
#include "sanitise.h"

static unsigned long *aio_ctxp;

static void sanitise_io_setup(struct syscallrecord *rec)
{
	/* ctxp must point to a zero-initialized aio_context_t */
	aio_ctxp = (unsigned long *) get_writable_address(sizeof(*aio_ctxp));
	*aio_ctxp = 0;
	rec->a2 = (unsigned long) aio_ctxp;
}

static void post_io_setup(struct syscallrecord *rec)
{
	struct object *obj;
	unsigned long ctx;

	if ((long) rec->retval != 0)
		return;

	ctx = *aio_ctxp;
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

	obj = get_random_object(OBJ_AIO_CTX, OBJ_GLOBAL);
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
