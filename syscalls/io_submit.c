/*
 * SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
	 struct iocb __user * __user *, iocbpp)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "fd.h"
#include "utils.h"

static int iocb_cmds[] = {
	IOCB_CMD_PREAD, IOCB_CMD_PWRITE, IOCB_CMD_FSYNC,
	IOCB_CMD_FDSYNC, IOCB_CMD_POLL, IOCB_CMD_NOOP,
};

static void sanitise_io_submit(struct syscallrecord *rec)
{
	struct iocb **iocbpp;
	struct iocb *iocbs;
	char *buf;
	unsigned int nr, i;

	rec->a1 = get_random_aio_ctx();

	nr = 1 + (rand() % 4);
	iocbs = (struct iocb *) get_writable_address(nr * sizeof(*iocbs));
	memset(iocbs, 0, nr * sizeof(*iocbs));
	iocbpp = (struct iocb **) get_writable_address(nr * sizeof(*iocbpp));

	buf = (char *) get_writable_address(4096);

	for (i = 0; i < nr; i++) {
		iocbs[i].aio_lio_opcode = iocb_cmds[rand() % ARRAY_SIZE(iocb_cmds)];
		iocbs[i].aio_fildes = get_random_fd();
		iocbs[i].aio_buf = (__u64)(unsigned long) buf;
		iocbs[i].aio_nbytes = 4096;
		iocbs[i].aio_offset = rand() % 65536;
		iocbs[i].aio_data = i;
		iocbpp[i] = &iocbs[i];
	}

	rec->a2 = nr;
	rec->a3 = (unsigned long) iocbpp;
}

static void post_io_submit(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > (long) rec->a2)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_io_submit = {
	.name = "io_submit",
	.num_args = 3,
	.argname = { [0] = "ctx_id", [1] = "nr", [2] = "iocbpp" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_io_submit,
	.post = post_io_submit,
};
