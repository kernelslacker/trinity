/*
 * SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
	 struct iocb __user * __user *, iocbpp)
 */
#include <linux/aio_abi.h>
#include <string.h>
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "fd.h"
#include "shm.h"
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

	nr = 1 + (rnd_modulo_u32(4));
	iocbs = (struct iocb *) get_writable_address(nr * sizeof(*iocbs));
	if (iocbs == NULL)
		return;
	memset(iocbs, 0, nr * sizeof(*iocbs));
	iocbpp = (struct iocb **) get_writable_address(nr * sizeof(*iocbpp));

	buf = (char *) get_writable_address(4096);
	if (iocbpp == NULL || buf == NULL) {
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}

	for (i = 0; i < nr; i++) {
		iocbs[i].aio_lio_opcode = iocb_cmds[rnd_modulo_u32(ARRAY_SIZE(iocb_cmds))];
		iocbs[i].aio_fildes = get_random_fd();
		iocbs[i].aio_buf = (__u64)(unsigned long) buf;
		iocbs[i].aio_nbytes = 4096;
		iocbs[i].aio_offset = rnd_modulo_u32(65536);
		iocbs[i].aio_data = i;
		if (rnd_modulo_u32(100) < 30) {
			int eventfd_fd = get_typed_fd(ARG_FD_EVENTFD);
			if (eventfd_fd >= 0) {
				iocbs[i].aio_flags |= IOCB_FLAG_RESFD;
				iocbs[i].aio_resfd = eventfd_fd;
			}
		}
		iocbpp[i] = &iocbs[i];
	}

	rec->a2 = nr;
	rec->a3 = (unsigned long) iocbpp;
	avoid_shared_buffer_inout(&rec->a3, nr * sizeof(struct iocb *));
}

static void post_io_submit(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > (long) rec->a2) {
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}
	if (ret > 0)
		__atomic_add_fetch(&shm->stats.aio_submitted, (unsigned long) ret,
				   __ATOMIC_RELAXED);
}

struct syscallentry syscall_io_submit = {
	.name = "io_submit",
	.num_args = 3,
	.argtype = { [0] = ARG_AIO_CTX },
	.argname = { [0] = "ctx_id", [1] = "nr", [2] = "iocbpp" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_io_submit,
	.post = post_io_submit,
};
