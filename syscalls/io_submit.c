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
	IOCB_CMD_PREAD, IOCB_CMD_PWRITE,
	IOCB_CMD_PREADV, IOCB_CMD_PWRITEV,
	IOCB_CMD_FSYNC, IOCB_CMD_FDSYNC,
	IOCB_CMD_POLL, IOCB_CMD_NOOP,
};

/*
 * Bias the iocb opcode against the underlying fd type so a meaningful
 * fraction of submissions reach the kernel's filesystem path instead
 * of bouncing off -ESPIPE / -EINVAL at io_submit_one().  PREAD/PWRITE
 * on a socket always -ESPIPEs; FSYNC on a pipe always -EINVALs; etc.
 *
 * A 15% slice keeps the original uncorrelated random pick so the
 * EINVAL/ESPIPE error paths still get coverage.  When the fd is not
 * tracked in the global fd hash (child-private, just-accepted socket,
 * untracked kernel-opened fd) fall back to the random pick — we have
 * no information to bias on.
 */
static int pick_iocb_opcode_for_fd(int fd)
{
	struct fd_hash_entry *e;

	if (rnd_modulo_u32(100) < 15)
		return iocb_cmds[rnd_modulo_u32(ARRAY_SIZE(iocb_cmds))];

	if (fd < 0)
		return iocb_cmds[rnd_modulo_u32(ARRAY_SIZE(iocb_cmds))];

	e = fd_hash_lookup(fd);
	if (e == NULL)
		return iocb_cmds[rnd_modulo_u32(ARRAY_SIZE(iocb_cmds))];

	switch (e->type) {
	case OBJ_FD_TESTFILE:
	case OBJ_FD_PAGECACHE:
	case OBJ_FD_MEMFD:
	case OBJ_FD_MEMFD_SECRET:
	case OBJ_FD_DEVFILE: {
		static const int file_cmds[] = {
			IOCB_CMD_PREAD, IOCB_CMD_PWRITE,
			IOCB_CMD_PREADV, IOCB_CMD_PWRITEV,
			IOCB_CMD_FSYNC, IOCB_CMD_FDSYNC,
			IOCB_CMD_NOOP,
		};
		return file_cmds[rnd_modulo_u32(ARRAY_SIZE(file_cmds))];
	}
	case OBJ_FD_PIPE:
		/*
		 * FSYNC/FDSYNC on a pipe -EINVAL.  PREAD on the writer
		 * end (and PWRITE on the reader end) -EBADF.  Route each
		 * side to the operation that actually exercises the
		 * pipe ->read_iter / ->write_iter path, mixing in POLL
		 * since pipes feed ->poll correctly.
		 */
		if (objpool_check(e->obj, OBJ_FD_PIPE) &&
		    e->obj->pipeobj.reader)
			return (rnd_modulo_u32(2) == 0) ?
				IOCB_CMD_PREAD : IOCB_CMD_POLL;
		return (rnd_modulo_u32(2) == 0) ?
			IOCB_CMD_PWRITE : IOCB_CMD_POLL;
	case OBJ_FD_SOCKET:
	case OBJ_FD_EVENTFD:
	case OBJ_FD_TIMERFD:
	case OBJ_FD_SIGNALFD:
	case OBJ_FD_INOTIFY:
	case OBJ_FD_FANOTIFY: {
		static const int pollable_cmds[] = {
			IOCB_CMD_POLL, IOCB_CMD_NOOP,
		};
		return pollable_cmds[rnd_modulo_u32(ARRAY_SIZE(pollable_cmds))];
	}
	default:
		return iocb_cmds[rnd_modulo_u32(ARRAY_SIZE(iocb_cmds))];
	}
}

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
		iocbs[i].aio_fildes = get_random_fd();
		iocbs[i].aio_lio_opcode = pick_iocb_opcode_for_fd(iocbs[i].aio_fildes);
		iocbs[i].aio_buf = (__u64)(unsigned long) buf;
		iocbs[i].aio_nbytes = 4096;
		iocbs[i].aio_offset = rnd_modulo_u32(65536);
		iocbs[i].aio_data = rnd_u64();
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

	/*
	 * Snapshot the post-relocation iocbpp address so the post handler
	 * can walk the iocbs even if a sibling-syscall scribble lands on
	 * rec->a3 between syscall return and post execution.  Matches the
	 * io_setup pattern around its ctxp out-pointer.
	 */
	rec->post_state = rec->a3;
}

static void post_io_submit(struct syscallrecord *rec)
{
	struct iocb **iocbpp;
	long ret = (long) rec->retval;
	long i;

	if (ret == -1L)
		return;
	if (ret < 0 || ret > (long) rec->a2) {
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}
	if (ret == 0)
		return;

	__atomic_add_fetch(&shm->stats.aio_submitted, (unsigned long) ret,
			   __ATOMIC_RELAXED);

	iocbpp = (struct iocb **) rec->post_state;
	if (iocbpp == NULL)
		return;
	if (looks_like_corrupted_ptr(rec, iocbpp)) {
		rec->post_state = 0;
		return;
	}

	/*
	 * Publish the (ctx, aio_data) cookie for every iocb the kernel
	 * accepted, so sanitise_io_cancel can pick one and build a
	 * cancel request the kernel will actually find.  Iocbs the
	 * kernel rejected (indices >= ret) are skipped — io_submit
	 * guarantees the first `ret` iocbs were the ones queued, and
	 * those beyond it never reached io_submit_one().
	 */
	for (i = 0; i < ret; i++) {
		struct iocb *iocb = iocbpp[i];
		struct object *obj;

		if (iocb == NULL)
			continue;
		if (looks_like_corrupted_ptr(rec, iocb))
			continue;

		obj = alloc_object();
		obj->aio_iocb_obj.ctx = rec->a1;
		obj->aio_iocb_obj.aio_data = iocb->aio_data;
		add_object(obj, OBJ_LOCAL, OBJ_AIO_IOCB);
	}
}

struct syscallentry syscall_io_submit = {
	.name = "io_submit",
	.num_args = 3,
	.argtype = { [0] = ARG_AIO_CTX, [1] = ARG_LEN, [2] = ARG_ADDRESS },
	.argname = { [0] = "ctx_id", [1] = "nr", [2] = "iocbpp" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_io_submit,
	.post = post_io_submit,
};
