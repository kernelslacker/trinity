/*
 * SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
	 struct io_event __user *, result)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "fd.h"

static void sanitise_io_cancel(struct syscallrecord *rec)
{
	struct iocb *iocb;
	struct io_event *result;
	struct object *pool_obj = NULL;

	iocb = (struct iocb *) get_writable_address(sizeof(*iocb));
	if (iocb == NULL)
		return;
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_lio_opcode = IOCB_CMD_PREAD;
	iocb->aio_fildes = get_random_fd();
	iocb->aio_buf = (__u64)(unsigned long) get_writable_address(4096);
	iocb->aio_nbytes = 4096;

	/*
	 * 60% of the time, pick a real outstanding (ctx, aio_data) from
	 * the OBJ_AIO_IOCB pool published by post_io_submit so the kernel
	 * actually finds the request and runs its ->cancel handler.  The
	 * remaining 40% keep the original random-iocb path so the
	 * not-found / EINVAL branch in __io_submit_cancel keeps coverage.
	 *
	 * Empty pool falls through to 100% random, which is what shipped
	 * before the pool was introduced.
	 */
	if (rnd_modulo_u32(100) < 60 &&
	    objects_pool_empty(OBJ_LOCAL, OBJ_AIO_IOCB) == false) {
		pool_obj = get_random_object(OBJ_AIO_IOCB, OBJ_LOCAL);
		if (objpool_check(pool_obj, OBJ_AIO_IOCB)) {
			rec->a1 = pool_obj->aio_iocb_obj.ctx;
			iocb->aio_data = pool_obj->aio_iocb_obj.aio_data;
		}
	}

	result = (struct io_event *) get_writable_address(sizeof(*result));
	if (result == NULL)
		return;
	memset(result, 0, sizeof(*result));

	rec->a2 = (unsigned long) iocb;
	rec->a3 = (unsigned long) result;

	avoid_shared_buffer_out(&rec->a3, sizeof(struct io_event));
}

struct syscallentry syscall_io_cancel = {
	.name = "io_cancel",
	.num_args = 3,
	.argtype = { [0] = ARG_AIO_CTX },
	.argname = { [0] = "ctx_id", [1] = "iocb", [2] = "result" },
	.group = GROUP_VFS,
	.sanitise = sanitise_io_cancel,
};
