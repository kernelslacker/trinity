/*
 * SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
	 struct iocb __user * __user *, iocbpp)
 */
#include <linux/aio_abi.h>
#include <poll.h>
#include <sys/uio.h>
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
	unsigned long ctx;
	unsigned int nr, i;

	/*
	 * Precondition: ctx_id (a1) must be a live aio_context_t the kernel
	 * has on hand or io_submit short-circuits with -EINVAL inside
	 * lookup_ioctx() before the iocb import / queueing path runs.
	 * gen_arg_aio_ctx returns 0 (or 1/8 of the time a raw rand64) until
	 * a real io_setup has published into OBJ_AIO_CTX; seed one inline so
	 * io_submit reaches the productive kernel path even on the very
	 * first call in the child.
	 */
	ctx = seed_aio_ctx_if_empty();
	if (ctx != 0)
		rec->a1 = ctx;

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

	/*
	 * Per-opcode aio_buf / aio_nbytes have different meanings inside the
	 * kernel: PREAD/PWRITE want a byte buffer + byte count, PREADV/PWRITEV
	 * want a struct iovec[] + iovec count, POLL packs the requested poll
	 * events into the low 16 bits of aio_buf (kernel rejects with -EINVAL
	 * if any high bit is set: see aio_poll() / aio_prep_rw()), and FSYNC
	 * / FDSYNC / NOOP ignore both.  The previous unconditional
	 * "aio_buf = buf, aio_nbytes = 4096" fill -EFAULT'd inside import_iovec
	 * on PREADV/PWRITEV (4096 bogus iovecs interpreted from raw data)
	 * and -EINVAL'd on POLL (a heap address has high bits set), so those
	 * opcodes never reached the kernel's productive vectored-IO / poll
	 * paths.  Build a small shared iovec[] scratch pool inside `buf` and
	 * dispatch by opcode below.
	 */
	{
		struct iovec *iovec_pool;
		unsigned int j;
		const unsigned int IOV_POOL_LEN = 4;
		const unsigned int IOV_SLICE_SZ = 1024;

		iovec_pool = (struct iovec *)
			get_writable_address(IOV_POOL_LEN * sizeof(*iovec_pool));
		if (iovec_pool != NULL) {
			for (j = 0; j < IOV_POOL_LEN; j++) {
				iovec_pool[j].iov_base = buf + j * IOV_SLICE_SZ;
				iovec_pool[j].iov_len = IOV_SLICE_SZ;
			}
		}

		for (i = 0; i < nr; i++) {
			iocbs[i].aio_fildes = get_random_fd();
			iocbs[i].aio_lio_opcode = pick_iocb_opcode_for_fd(iocbs[i].aio_fildes);
			iocbs[i].aio_data = rnd_u64();

			switch (iocbs[i].aio_lio_opcode) {
			case IOCB_CMD_PREAD:
			case IOCB_CMD_PWRITE:
				iocbs[i].aio_buf = (__u64)(uintptr_t) buf;
				iocbs[i].aio_nbytes = 4096;
				iocbs[i].aio_offset = rnd_modulo_u32(65536);
				break;
			case IOCB_CMD_PREADV:
			case IOCB_CMD_PWRITEV:
				if (iovec_pool == NULL) {
					/* No iovec scratch -- downgrade to NOOP
					 * rather than feed import_iovec garbage. */
					iocbs[i].aio_lio_opcode = IOCB_CMD_NOOP;
					iocbs[i].aio_buf = 0;
					iocbs[i].aio_nbytes = 0;
					iocbs[i].aio_offset = 0;
					break;
				}
				iocbs[i].aio_buf = (__u64)(uintptr_t) iovec_pool;
				iocbs[i].aio_nbytes = 1 + rnd_modulo_u32(IOV_POOL_LEN);
				iocbs[i].aio_offset = rnd_modulo_u32(65536);
				break;
			case IOCB_CMD_POLL: {
				/* aio_poll reads the requested events as a
				 * __poll_t (u16) from the low bits of aio_buf
				 * and the kernel rejects any value that does
				 * not fit in u16.  Pack a small mask. */
				static const unsigned short poll_masks[] = {
					POLLIN, POLLOUT, POLLIN | POLLOUT,
					POLLPRI, POLLRDNORM, POLLWRNORM,
					POLLERR, POLLHUP,
				};
				iocbs[i].aio_buf =
					poll_masks[rnd_modulo_u32(ARRAY_SIZE(poll_masks))];
				iocbs[i].aio_nbytes = 0;
				iocbs[i].aio_offset = 0;
				break;
			}
			case IOCB_CMD_FSYNC:
			case IOCB_CMD_FDSYNC:
			case IOCB_CMD_NOOP:
			default:
				/* aio_buf / aio_nbytes / aio_offset are
				 * ignored by these opcodes; leave them zero
				 * so a future opcode addition does not inherit
				 * stale fields. */
				iocbs[i].aio_buf = 0;
				iocbs[i].aio_nbytes = 0;
				iocbs[i].aio_offset = 0;
				break;
			}

			if (rnd_modulo_u32(100) < 30) {
				int eventfd_fd = get_typed_fd(ARG_FD_EVENTFD);
				if (eventfd_fd >= 0) {
					iocbs[i].aio_flags |= IOCB_FLAG_RESFD;
					iocbs[i].aio_resfd = eventfd_fd;
				}
			}
			iocbpp[i] = &iocbs[i];
		}
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
	if (ret < 0 || ret > (long) get_arg_snapshot(rec, 2)) {
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}
	if (ret == 0)
		return;

	__atomic_add_fetch(&shm->stats.aio.submitted, (unsigned long) ret,
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
		__u64 aio_data;

		if (iocb == NULL)
			continue;
		if (looks_like_corrupted_ptr(rec, iocb))
			continue;

		/*
		 * looks_like_corrupted_ptr is shape-only -- a heap-shaped
		 * iocb whose iocbpp[i] slot was scribbled by a sibling to a
		 * heap-band value pointing at unmapped memory, or whose
		 * underlying iocbs[] region was torn down by a raw munmap
		 * that bypassed trinity's get_writable_address bookkeeping,
		 * still reaches the aio_data load below.  Range-probe + copy
		 * through the post_snapshot_or_skip sigsetjmp window so the
		 * .post sample is dropped instead of faulting on the load.
		 */
		if (!post_snapshot_or_skip(&aio_data, &iocb->aio_data,
					   sizeof(aio_data)))
			continue;

		obj = alloc_object();
		obj->aio_iocb_obj.ctx = rec->a1;
		obj->aio_iocb_obj.aio_data = aio_data;
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
	.arg_snapshot_mask = (1u << 1),
};
