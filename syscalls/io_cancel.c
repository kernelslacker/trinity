/*
 * SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
	 struct io_event __user *, result)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "fd.h"

static void sanitise_io_cancel(struct syscallrecord *rec)
{
	struct iocb *iocb;
	struct io_event *result;

	iocb = (struct iocb *) get_writable_address(sizeof(*iocb));
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_lio_opcode = IOCB_CMD_PREAD;
	iocb->aio_fildes = get_random_fd();
	iocb->aio_buf = (__u64)(unsigned long) get_writable_address(4096);
	iocb->aio_nbytes = 4096;

	result = (struct io_event *) get_writable_address(sizeof(*result));
	memset(result, 0, sizeof(*result));

	rec->a2 = (unsigned long) iocb;
	rec->a3 = (unsigned long) result;
}

struct syscallentry syscall_io_cancel = {
	.name = "io_cancel",
	.num_args = 3,
	.arg1name = "ctx_id",
	.arg1type = ARG_ADDRESS,
	.arg2name = "iocb",
	.arg3name = "result",
	.group = GROUP_VFS,
	.sanitise = sanitise_io_cancel,
};
