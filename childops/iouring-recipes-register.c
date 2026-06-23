/*
 * iouring-recipes-register -- registered-buffer / registered-file /
 * provided-buffer / msg-ring / registered-eventfd / files-update recipe
 * family for the iouring-recipes catalogue.
 *
 * recipe_fixed_buffer_read and recipe_write_read_fixed draw from the
 * parent's mapping pool and publish their drawn range to the pool-race
 * statics defined in iouring-recipes.c so the dispatcher's fault
 * handler can route an in-range SEGV/SIGBUS to the sigsetjmp landing
 * pad.  recipe_msg_ring stands up a second inner ring via
 * iour_ring_setup; recipe_eventfd_recursive drives the registered-
 * eventfd recursive-wakeup path.
 *
 * See childops/iouring-recipes.c for the dispatcher and the shared
 * pool-race fault handler; see iouring-recipes-internal.h for the
 * cross-TU symbol boundary.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/io_uring.h>

#include "childops-iouring.h"
#include "compat.h"
#include "errno-classify.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "stats.h"
#include "syscall-gate.h"
#include "trinity.h"

#include "childops/iouring-recipes-internal.h"

/* ------------------------------------------------------------------ *
 * Recipe 9: READ_FIXED with IORING_REGISTER_BUFFERS (registered fixed buffers)
 *
 * Register a page-sized buffer with the ring, then submit
 * IORING_OP_READ_FIXED targeting buffer index 0 against /dev/zero.
 * This exercises the registered-buffer fast path: the kernel skips the
 * per-syscall get_user_pages and reads directly into the pre-pinned
 * region.  Unregister before teardown to exercise the unpin path.
 * ------------------------------------------------------------------ */
bool recipe_fixed_buffer_read(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct iovec iov;
	struct io_uring_sqe sqe;
	struct map *m = NULL;
	void *buf = NULL;
	size_t buf_sz = 0;
	bool ok = false;
	int r;

	/* Draw the registered-buffer backing storage from the parent's
	 * inherited mapping pool.  Sibling iouring children draw from the
	 * same pool, so the kernel will sometimes see two rings register the
	 * same physical pages — that overlap is the CV.4 target, exercising
	 * io_uring's per-buffer pinning / tracking against shared backing.
	 *
	 * The pool owns the mapping: do NOT munmap on cleanup, and do NOT
	 * memset / fill before submission — sibling ops may be reading from
	 * the same page concurrently.  The READ_FIXED below WILL overwrite
	 * the buffer with /dev/zero data, which is the intentional cross-
	 * child mutation we want the kernel to race against.
	 *
	 * Filter the pool draw on PROT_WRITE: IORING_REGISTER_BUFFERS pins
	 * the user pages with FOLL_WRITE (so a non-writable mapping fails
	 * register with -EFAULT before exercising the fast path), and the
	 * READ_FIXED below has the kernel writing /dev/zero data into the
	 * buffer — drawing a PROT_READ-only or PROT_NONE pool entry would
	 * either short-circuit the register or fault on the kernel-side
	 * copy.  Either way the recipe never reaches the fixed-buffer
	 * fast path it's meant to exercise. */
	m = get_map_with_prot(PROT_WRITE);
	if (m == NULL)
		goto out;
	buf = m->ptr;
	buf_sz = m->size;

	/* Publish drawn pool range to the iouring_recipes_pool_race_handler
	 * so an in-range SEGV/SIGBUS later inside this recipe gets caught
	 * as a pool race; out-of-range faults stay routed to the default
	 * handler. */
	iouring_recipes_pool_race_addr_low  = (uintptr_t)buf;
	iouring_recipes_pool_race_addr_high = (uintptr_t)buf + buf_sz;

	iov.iov_base = buf;
	iov.iov_len  = buf_sz;

	r = (int)trinity_raw_syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_BUFFERS, &iov, 1);
	if (r < 0)
		goto out;
	s->registered_buf = true;

	s->open_fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
	if (s->open_fd < 0)
		goto out;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_READ_FIXED;
	sqe.fd        = s->open_fd;
	sqe.addr      = (__u64)(uintptr_t)buf;
	sqe.len       = (unsigned int)buf_sz;
	sqe.buf_index = 0;
	sqe.user_data = 80;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 10: WRITE_FIXED + READ_FIXED using the same registered buffer
 *
 * Register one buffer, write into it via WRITE_FIXED on a pipe, then
 * read it back via READ_FIXED.  Both ops share buffer index 0 and are
 * submitted as a linked pair.  This exercises the fixed-buffer fast
 * path in both directions within a structured sequence.
 * ------------------------------------------------------------------ */
bool recipe_write_read_fixed(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	struct iovec iov;
	struct map *m = NULL;
	void *buf = NULL;
	size_t buf_sz = 0;
	bool ok = false;
	int r;

	/* Same pool draw as recipe_fixed_buffer_read above — the registered
	 * buffer comes from the parent's inherited mapping pool, shared with
	 * sibling iouring children.  See the commentary there for the
	 * rationale and the brick-risks (no munmap, no memset).
	 *
	 * The 64-byte WRITE_FIXED publishes whatever happens to be in the
	 * pool entry into the pipe, then READ_FIXED reads it back; the write
	 * content is intentionally undefined — io_uring users routinely
	 * register buffers without zeroing them, and the shared-pool overlap
	 * is what we want the kernel's fixed-buffer fast path to race on.
	 *
	 * Filter the pool draw on PROT_READ | PROT_WRITE: WRITE_FIXED has
	 * the kernel reading from the buffer (needs PROT_READ) and
	 * READ_FIXED has it writing back into the buffer (needs PROT_WRITE),
	 * and IORING_REGISTER_BUFFERS itself pins with FOLL_WRITE.  Both
	 * directions and the register pin all have to succeed for the linked
	 * pair to actually exercise the fixed-buffer fast path. */
	m = get_map_with_prot(PROT_READ | PROT_WRITE);
	if (m == NULL)
		goto out;
	buf = m->ptr;
	buf_sz = m->size;

	/* Publish drawn pool range — see recipe_fixed_buffer_read for the
	 * full rationale. */
	iouring_recipes_pool_race_addr_low  = (uintptr_t)buf;
	iouring_recipes_pool_race_addr_high = (uintptr_t)buf + buf_sz;

	iov.iov_base = buf;
	iov.iov_len  = buf_sz;

	r = (int)trinity_raw_syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_BUFFERS, &iov, 1);
	if (r < 0)
		goto out;
	s->registered_buf = true;

	if (pipe(s->pipefd) < 0)
		goto out;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_WRITE_FIXED;
	sqes[0].fd        = s->pipefd[1];
	sqes[0].addr      = (__u64)(uintptr_t)buf;
	sqes[0].len       = 64;
	sqes[0].buf_index = 0;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 90;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_READ_FIXED;
	sqes[1].fd        = s->pipefd[0];
	sqes[1].addr      = (__u64)(uintptr_t)buf;
	sqes[1].len       = 64;
	sqes[1].buf_index = 0;
	sqes[1].user_data = 91;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 2);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 11: PROVIDE_BUFFERS + recv into provided buffer + REMOVE_BUFFERS
 *
 * Register a buffer ring via IORING_OP_PROVIDE_BUFFERS so the kernel
 * manages buffer selection, submit a RECV with IOSQE_BUFFER_SELECT so
 * the kernel picks a buffer from the group, then remove the buffers.
 * Exercises the provided-buffer lifecycle: add → select → consume →
 * remove, including the CQE upper-16-bits buffer-ID reporting path.
 * ------------------------------------------------------------------ */
bool recipe_provide_buffers(struct iour_recipe_state *s, bool *unsupported __unused__)
{
#define PBUF_GROUP_ID	1
#define PBUF_COUNT	4
#define PBUF_BUF_SIZE	256

	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	bool ok = false;
	int r;

	s->malloc_buf = malloc((size_t)PBUF_COUNT * PBUF_BUF_SIZE);
	if (!s->malloc_buf)
		goto out;
	memset(s->malloc_buf, 0, (size_t)PBUF_COUNT * PBUF_BUF_SIZE);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, s->sock) < 0)
		goto out;

	/* PROVIDE_BUFFERS: addr=start, len=buf_size, fd=count, off=start_bid. */
	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_PROVIDE_BUFFERS;
	sqe.addr      = (__u64)(uintptr_t)s->malloc_buf;
	sqe.len       = PBUF_BUF_SIZE;
	sqe.fd        = PBUF_COUNT;
	sqe.off       = 0;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = 100;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		goto out;
	iour_drain_cqes(ctx);
	s->provided_buf_active   = true;
	s->provided_buf_group_id = PBUF_GROUP_ID;
	s->provided_buf_count    = PBUF_COUNT;

	{
		const char msg[] = "recipe";
		ssize_t w __unused__ = write(s->sock[0], msg, sizeof(msg));
	}

	/* RECV with IOSQE_BUFFER_SELECT — kernel picks buffer from group. */
	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_RECV;
	sqe.fd        = s->sock[1];
	sqe.len       = PBUF_BUF_SIZE;
	sqe.flags     = IOSQE_BUFFER_SELECT;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = 101;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		goto out;
	iour_drain_cqes(ctx);

	/* REMOVE_BUFFERS: fd=count, buf_group=group_id. */
	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_REMOVE_BUFFERS;
	sqe.fd        = PBUF_COUNT;
	sqe.buf_group = PBUF_GROUP_ID;
	sqe.user_data = 102;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		goto out;
	iour_drain_cqes(ctx);
	s->provided_buf_active = false;

	ok = true;
out:
	return ok;

#undef PBUF_GROUP_ID
#undef PBUF_COUNT
#undef PBUF_BUF_SIZE
}

/* ------------------------------------------------------------------ *
 * Recipe 12: MSG_RING — inter-ring notification
 *
 * Create a second io_uring ring, then send a notification from the
 * primary ring (ctx->fd) to the secondary ring via IORING_OP_MSG_RING.
 * This exercises the cross-ring messaging path added in Linux 5.18,
 * including CQE posting into a foreign ring's completion queue.
 * First failure with ENOSYS latches the recipe off.
 * ------------------------------------------------------------------ */
#ifndef IORING_OP_MSG_RING
#define IORING_OP_MSG_RING	40
#endif

bool recipe_msg_ring(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	bool ok = false;
	int r;

	{
		struct io_uring_params p;

		memset(&p, 0, sizeof(p));
		if (iour_ring_setup(&p, (unsigned int)RAND_NEGATIVE_OR(8),
				    &s->inner) != IOUR_SUPPORTED)
			goto out;
		s->inner_active = true;
	}

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_MSG_RING;
	sqe.fd        = s->inner.fd;
	sqe.len       = 0;
	sqe.off       = 0xdeadbeefULL;
	sqe.user_data = 110;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (is_syscall_unsupported(errno) || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}

	iour_drain_cqes(ctx);
	iour_drain_cqes(&s->inner);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 13: STATX with a registered file index
 *
 * Register one fd with the ring's file table, then submit
 * IORING_OP_STATX targeting the registered fd via IOSQE_FIXED_FILE.
 * This exercises the registered-file fast path that avoids the
 * per-syscall fdget_pos lookup.
 * ------------------------------------------------------------------ */
bool recipe_statx_fixed_file(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct statx stx;
	int fds[1];
	bool ok = false;
	int r;
	static const char empty[] = "";

	s->open_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (s->open_fd < 0)
		goto out;

	fds[0] = s->open_fd;
	r = (int)trinity_raw_syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_FILES, fds, 1);
	if (r < 0)
		goto out;
	s->registered_files = true;

	memset(&stx, 0, sizeof(stx));

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_STATX;
	sqe.fd          = 0;
	sqe.flags       = IOSQE_FIXED_FILE;
	sqe.addr        = (__u64)(uintptr_t)empty;
	sqe.len         = AT_STATX_SYNC_AS_STAT;
	sqe.off         = (__u64)(uintptr_t)&stx;
	sqe.statx_flags = AT_EMPTY_PATH;
	sqe.user_data   = 120;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe: FILES_UPDATE on a pre-registered file table
 *
 * Register 4 placeholder slots, then submit FILES_UPDATE to swap one
 * slot in via the SQE.  The cleanup path UNREGISTERs the table.
 * ------------------------------------------------------------------ */
bool recipe_files_update(struct iour_recipe_state *s, bool *unsupported __unused__)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int regfds[4] = { -1, -1, -1, -1 };
	int newfds[1];
	int r;

	s->open_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (s->open_fd < 0)
		return false;

	r = (int)trinity_raw_syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_FILES, regfds, 4);
	if (r < 0)
		return false;
	s->registered_files = true;

	newfds[0] = s->open_fd;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_FILES_UPDATE;
	sqe.fd        = 0;
	sqe.addr      = (__u64)(uintptr_t)newfds;
	sqe.len       = 1;
	sqe.off       = 0;
	sqe.user_data = 380;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: registered eventfd + recursive completion exerciser
 *
 * IORING_REGISTER_EVENTFD installs an eventfd as the ring's CQE
 * notification target.  Submitting an SQE that reads from that same
 * registered eventfd creates a feedback path: each CQE posted by the
 * read signals the registered eventfd, incrementing its counter, which
 * wakes the next pending read SQE, which on completion posts another
 * CQE — and so on.  Upstream commit 04fe9aeb4f3c fixed a bug class
 * where this path could stick / recurse on the wakeup signal when many
 * CQEs landed in quick succession.
 *
 * The recipe registers the eventfd against the ring (50% async via
 * IORING_REGISTER_EVENTFD_ASYNC), submits a small batch (4–8) of
 * IORING_OP_READ SQEs targeting that fd, then writes the eventfd many
 * times to drive the recursive wakeup path while the ring drains the
 * read completions.  Drain is bounded; first EINVAL/ENOTTY on register
 * latches the recipe off.
 * ------------------------------------------------------------------ */
#ifndef IORING_REGISTER_EVENTFD
#define IORING_REGISTER_EVENTFD		4
#endif
#ifndef IORING_UNREGISTER_EVENTFD
#define IORING_UNREGISTER_EVENTFD	5
#endif
#ifndef IORING_REGISTER_EVENTFD_ASYNC
#define IORING_REGISTER_EVENTFD_ASYNC	7
#endif

bool recipe_eventfd_recursive(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ring *ctx = s->ctx;
	struct io_uring_sqe sqes[8];
	eventfd_t bufs[8];
	uint64_t one = 1;
	unsigned int nreads, reg_op, head, tail, reaped, spins, i;
	bool ok = false;
	bool registered = false;
	int r;

	s->evfd = eventfd(0, EFD_NONBLOCK);
	if (s->evfd < 0)
		goto out;

	reg_op = ONE_IN(2) ? IORING_REGISTER_EVENTFD_ASYNC
			   : IORING_REGISTER_EVENTFD;

	r = (int)trinity_raw_syscall(__NR_io_uring_register, ctx->fd, reg_op,
			 &s->evfd, 1);
	if (r < 0) {
		__atomic_add_fetch(&shm->stats.iouring_eventfd_register_fail,
				   1, __ATOMIC_RELAXED);
		if (errno == EINVAL || errno == ENOTTY) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	registered = true;
	__atomic_add_fetch(&shm->stats.iouring_eventfd_register_ok, 1,
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.iouring_eventfd_recursive_runs, 1,
			   __ATOMIC_RELAXED);

	nreads = 4 + rnd_modulo_u32(5);

	for (i = 0; i < nreads; i++) {
		sqe_clear(&sqes[i]);
		sqes[i].opcode    = IORING_OP_READ;
		sqes[i].fd        = s->evfd;
		sqes[i].addr      = (__u64)(uintptr_t)&bufs[i];
		sqes[i].len       = sizeof(eventfd_t);
		sqes[i].user_data = 600 + i;
	}

	if (!iour_submit_sqes(ctx, sqes, nreads))
		goto cleanup;

	r = (int)trinity_raw_syscall(__NR_io_uring_enter, ctx->fd, nreads, 0, 0, NULL, 0);
	if (r < 0)
		goto cleanup;

	/* Fire many wakeups in quick succession.  Each write increments
	 * the eventfd counter, the kernel wakes a blocked read SQE which
	 * consumes the counter and posts a CQE, and the CQE post itself
	 * signals the registered eventfd — the recursive wakeup loop
	 * fixed upstream by 04fe9aeb4f3c. */
	for (i = 0; i < 16; i++) {
		ssize_t w __unused__ = write(s->evfd, &one, sizeof(one));
	}

	/* Bounded drain.  Non-blocking GETEVENTS lets the kernel post
	 * completions; cap at 32 spins / 32 CQEs so a wedged kernel can't
	 * hang us, and break early once every read SQE has completed. */
	reaped = 0;
	for (spins = 0; spins < 32 && reaped < 32; spins++) {
		(void)trinity_raw_syscall(__NR_io_uring_enter, ctx->fd, 0, 0,
			      IORING_ENTER_GETEVENTS, NULL, 0);

		head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
		while (head != tail && reaped < 32) {
			head++;
			reaped++;
		}
		__sync_synchronize();
		ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);

		if (reaped >= nreads)
			break;
	}

	if (reaped)
		__atomic_add_fetch(&shm->stats.iouring_eventfd_recursive_cqes,
				   reaped, __ATOMIC_RELAXED);

	ok = true;

cleanup:
	if (registered) {
		(void)trinity_raw_syscall(__NR_io_uring_register, ctx->fd,
			      IORING_UNREGISTER_EVENTFD, NULL, 0);
	}
out:
	return ok;
}
