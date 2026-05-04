/*
 * iouring_recipes - structured io_uring submission sequences.
 *
 * The default io_uring_enter path fills SQEs with random values, which
 * rarely produces structurally valid submissions.  Deep io_uring code
 * paths — linked-SQE chains, drain ordering, registered-buffer ops,
 * async cancellation interactions — stay cold unless the kernel sees
 * semantically coherent request sequences.
 *
 * Each recipe here is a self-contained sequence: set up a ring, submit
 * a purposefully constructed batch of SQEs, reap the CQEs, and tear the
 * ring down.  The interesting surface is the sequence of state transitions
 * the kernel traverses, not the argument values themselves — so args are
 * kept intentionally simple (zero offsets, page-size buffers, loopback
 * addresses) to avoid false negatives from EFAULT or EINVAL before the
 * kernel reaches the code path we care about.
 *
 * Where a recipe exercises a kernel feature that may be absent (ENOSYS,
 * missing config), it latches a per-recipe disabled flag in shm so
 * siblings skip the probe on subsequent iterations.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <linux/io_uring.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#define __NR_io_uring_register	427
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_SQES		0x10000000ULL
#endif

/*
 * Local ring context — set up per-invocation, torn down before return.
 * Keeps all mmap'd regions together so cleanup is a single goto-chain.
 */
struct iour_ctx {
	int		fd;
	void		*sq_ring;
	void		*cq_ring;	/* may equal sq_ring if SINGLE_MMAP */
	void		*sqes;
	size_t		sq_ring_sz;
	size_t		cq_ring_sz;	/* 0 when SINGLE_MMAP */
	size_t		sqes_sz;
	bool		single_mmap;

	unsigned int	sq_entries;
	unsigned int	cq_entries;

	/* SQ ring field offsets within the mmap'd region. */
	unsigned int	sq_off_head;
	unsigned int	sq_off_tail;
	unsigned int	sq_off_mask;
	unsigned int	sq_off_array;

	/* CQ ring field offsets within the mmap'd region. */
	unsigned int	cq_off_head;
	unsigned int	cq_off_tail;
	unsigned int	cq_off_mask;
	unsigned int	cq_off_cqes;
};

static inline unsigned int ring_u32(void *ring, unsigned int off)
{
	return *(volatile unsigned int *)((char *)ring + off);
}

static inline void ring_store_u32(void *ring, unsigned int off, unsigned int v)
{
	*(volatile unsigned int *)((char *)ring + off) = v;
}

/*
 * Set up a private io_uring with the requested number of SQ entries.
 * Returns true on success; ctx is fully populated.  On failure, ctx is
 * zeroed and no resources need freeing.
 */
static bool iour_setup(struct iour_ctx *ctx, unsigned int entries)
{
	struct io_uring_params p;
	size_t sq_sz, cq_sz, sqes_sz;
	void *sq_ring, *cq_ring, *sqes;

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;

	memset(&p, 0, sizeof(p));
	ctx->fd = (int)syscall(__NR_io_uring_setup,
			       (unsigned int)RAND_NEGATIVE_OR(entries), &p);
	if (ctx->fd < 0)
		return false;

	/* SQ ring: sq_off.array offset + sq_entries * sizeof(u32). */
	sq_sz = (size_t)p.sq_off.array + (size_t)p.sq_entries * sizeof(unsigned int);
	/* CQ ring: cq_off.cqes offset + cq_entries * sizeof(io_uring_cqe). */
	cq_sz = (size_t)p.cq_off.cqes + (size_t)p.cq_entries * sizeof(struct io_uring_cqe);
	/* SQE array: sq_entries * sizeof(io_uring_sqe). */
	sqes_sz = (size_t)p.sq_entries * sizeof(struct io_uring_sqe);

	sq_ring = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, ctx->fd, IORING_OFF_SQ_RING);
	if (sq_ring == MAP_FAILED)
		goto fail_close;

	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		cq_ring = sq_ring;
		ctx->single_mmap = true;
	} else {
		cq_ring = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE,
			       ctx->fd, IORING_OFF_CQ_RING);
		if (cq_ring == MAP_FAILED) {
			munmap(sq_ring, sq_sz);
			goto fail_close;
		}
	}

	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, ctx->fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		if (!ctx->single_mmap)
			munmap(cq_ring, cq_sz);
		munmap(sq_ring, sq_sz);
		goto fail_close;
	}

	ctx->sq_ring    = sq_ring;
	ctx->sq_ring_sz = sq_sz;
	ctx->cq_ring    = cq_ring;
	ctx->cq_ring_sz = ctx->single_mmap ? 0 : cq_sz;
	ctx->sqes       = sqes;
	ctx->sqes_sz    = sqes_sz;

	ctx->sq_entries = p.sq_entries;
	ctx->cq_entries = p.cq_entries;

	ctx->sq_off_head  = p.sq_off.head;
	ctx->sq_off_tail  = p.sq_off.tail;
	ctx->sq_off_mask  = p.sq_off.ring_mask;
	ctx->sq_off_array = p.sq_off.array;

	ctx->cq_off_head  = p.cq_off.head;
	ctx->cq_off_tail  = p.cq_off.tail;
	ctx->cq_off_mask  = p.cq_off.ring_mask;
	ctx->cq_off_cqes  = p.cq_off.cqes;

	return true;

fail_close:
	close(ctx->fd);
	ctx->fd = -1;
	return false;
}

static void iour_teardown(struct iour_ctx *ctx)
{
	if (ctx->sqes)
		munmap(ctx->sqes, ctx->sqes_sz);
	if (ctx->cq_ring && !ctx->single_mmap)
		munmap(ctx->cq_ring, ctx->cq_ring_sz);
	if (ctx->sq_ring)
		munmap(ctx->sq_ring, ctx->sq_ring_sz);
	if (ctx->fd >= 0)
		close(ctx->fd);
}

/*
 * Place n SQEs starting at sqe[] into the submission ring and update the
 * published tail.  Returns false if n exceeds the available ring space.
 */
static bool iour_submit_sqes(struct iour_ctx *ctx,
			      struct io_uring_sqe *sqe, unsigned int n)
{
	unsigned int mask  = ring_u32(ctx->sq_ring, ctx->sq_off_mask);
	unsigned int head  = ring_u32(ctx->sq_ring, ctx->sq_off_head);
	unsigned int tail  = ring_u32(ctx->sq_ring, ctx->sq_off_tail);
	unsigned int avail = ctx->sq_entries - (tail - head);
	unsigned int *sq_array;
	struct io_uring_sqe *sqes = ctx->sqes;
	unsigned int i;

	if (n > avail)
		return false;

	sq_array = (unsigned int *)((char *)ctx->sq_ring + ctx->sq_off_array);

	for (i = 0; i < n; i++) {
		unsigned int slot = (tail + i) & mask;

		sqes[slot] = sqe[i];
		sq_array[slot] = slot;
	}

	__sync_synchronize();
	ring_store_u32(ctx->sq_ring, ctx->sq_off_tail, tail + n);
	return true;
}

/*
 * Submit n SQEs and optionally wait for min_complete CQEs.
 */
static int iour_enter(struct iour_ctx *ctx, unsigned int n,
		      unsigned int min_complete)
{
	return (int)syscall(__NR_io_uring_enter, ctx->fd, n, min_complete,
			    IORING_ENTER_GETEVENTS, NULL, 0);
}

/*
 * Drain all available CQEs from the completion ring, advancing the head.
 */
static void iour_drain_cqes(struct iour_ctx *ctx)
{
	unsigned int mask = ring_u32(ctx->cq_ring, ctx->cq_off_mask);
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;
	struct io_uring_cqe *cqes;

	cqes = (struct io_uring_cqe *)((char *)ctx->cq_ring + ctx->cq_off_cqes);
	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		(void)cqes[head & mask];
		head++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
}

static void sqe_clear(struct io_uring_sqe *s)
{
	memset(s, 0, sizeof(*s));
}

/*
 * A discoverable recipe sets *unsupported = true when it first encounters
 * ENOSYS or a missing kernel feature.  The dispatcher latches the recipe off
 * in shm so siblings stop probing.
 */
struct iour_recipe {
	const char *name;
	bool (*run)(struct iour_ctx *ctx, bool *unsupported);
};

/* ------------------------------------------------------------------ *
 * Recipe 1: NOP chain (sanity + linked-SQE chain dispatch)
 *
 * Submit three IORING_OP_NOP SQEs where the first two carry
 * IOSQE_IO_LINK so they execute as a linked sequence.  NOP has no
 * side effects; the target here is the chain-dispatch logic: the kernel
 * must propagate the linked state through two members before posting
 * the final unlinked completion.
 * ------------------------------------------------------------------ */
static bool recipe_nop_chain(struct iour_ctx *ctx,
			      bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[3];
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 1;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_NOP;
	sqes[1].flags     = IOSQE_IO_LINK;
	sqes[1].user_data = 2;

	sqe_clear(&sqes[2]);
	sqes[2].opcode    = IORING_OP_NOP;
	sqes[2].user_data = 3;

	if (!iour_submit_sqes(ctx, sqes, 3))
		return false;

	r = iour_enter(ctx, 3, 3);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe 2: TIMEOUT with IOSQE_IO_DRAIN
 *
 * Submit a NOP then a TIMEOUT with IOSQE_IO_DRAIN set.  Drain ordering
 * requires the kernel to complete all prior SQEs before starting the
 * timeout countdown — this exercises the drain-flag dispatch path and
 * the timeout-vs-drain interaction.
 * ------------------------------------------------------------------ */
static bool recipe_timeout_drain(struct iour_ctx *ctx,
				 bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[2];
	struct __kernel_timespec ts;
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_DRAIN;
	sqes[0].user_data = 10;

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000000;	/* 1 ms */

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_TIMEOUT;
	sqes[1].flags     = IOSQE_IO_DRAIN;
	sqes[1].addr      = (__u64)(uintptr_t)&ts;
	sqes[1].len       = 1;
	sqes[1].user_data = 11;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe 3: POLL_ADD multi-shot + POLL_REMOVE
 *
 * Create an eventfd, register a POLL_ADD with IORING_POLL_ADD_MULTI
 * so the kernel installs a persistent poll-wait, then immediately
 * submit a POLL_REMOVE targeting the same user_data.  This races the
 * removal against the poll-wait registration — the kernel must handle
 * the cancellation regardless of which path wins.
 * ------------------------------------------------------------------ */
#ifndef IORING_POLL_ADD_MULTI
#define IORING_POLL_ADD_MULTI	(1U << 0)
#endif

static bool recipe_poll_multishot(struct iour_ctx *ctx,
				  bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[2];
	int evfd = -1;
	bool ok = false;
	int r;

	evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (evfd < 0)
		goto out;

	/* POLL_ADD with IORING_POLL_ADD_MULTI (multi-shot). */
	sqe_clear(&sqes[0]);
	sqes[0].opcode        = IORING_OP_POLL_ADD;
	sqes[0].fd            = evfd;
	sqes[0].poll32_events = POLLIN;
	sqes[0].len           = IORING_POLL_ADD_MULTI;
	sqes[0].user_data     = 20;

	/* POLL_REMOVE by user_data to cancel the multi-shot above. */
	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_POLL_REMOVE;
	sqes[1].addr      = 20;
	sqes[1].user_data = 21;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	if (evfd >= 0)
		close(evfd);
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 4: SEND + RECV over a socketpair with linked SQEs
 *
 * Create a UNIX socketpair, link a SEND into a RECV.  IOSQE_IO_LINK
 * on the SEND means the RECV only starts when SEND completes — this
 * walks the linked-request dispatch and the UNIX socket I/O path
 * within a single submission batch.
 * ------------------------------------------------------------------ */
static bool recipe_send_recv_linked(struct iour_ctx *ctx,
				    bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[2];
	int sv[2] = { -1, -1 };
	char buf[32];
	bool ok = false;
	int r;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, sv) < 0)
		goto out;

	memset(buf, 's', sizeof(buf));

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_SEND;
	sqes[0].fd        = sv[0];
	sqes[0].addr      = (__u64)(uintptr_t)buf;
	sqes[0].len       = sizeof(buf);
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 30;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_RECV;
	sqes[1].fd        = sv[1];
	sqes[1].addr      = (__u64)(uintptr_t)buf;
	sqes[1].len       = sizeof(buf);
	sqes[1].user_data = 31;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 2);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	if (sv[0] >= 0) close(sv[0]);
	if (sv[1] >= 0) close(sv[1]);
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 5: OPENAT + CLOSE in linked SQEs (teardown race)
 *
 * Open /dev/null via IORING_OP_OPENAT then immediately chain a CLOSE.
 * The CLOSE uses fd=0 as a placeholder — it will produce EBADF or get
 * cancelled by the link chain.  The interesting path is the linked-
 * cancel sequence when the second request references a result not yet
 * available from the first.
 * ------------------------------------------------------------------ */
static bool recipe_openat_close_linked(struct iour_ctx *ctx,
				       bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[2];
	int r;
	static const char devnull[] = "/dev/null";

	sqe_clear(&sqes[0]);
	sqes[0].opcode     = IORING_OP_OPENAT;
	sqes[0].fd         = AT_FDCWD;
	sqes[0].addr       = (__u64)(uintptr_t)devnull;
	sqes[0].open_flags = O_RDONLY;
	sqes[0].flags      = IOSQE_IO_LINK;
	sqes[0].user_data  = 40;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_CLOSE;
	sqes[1].fd        = 0;
	sqes[1].user_data = 41;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe 6: SOCKET + SHUTDOWN in linked SQEs
 *
 * IORING_OP_SOCKET creates a TCP socket through the ring.  Linking a
 * SHUTDOWN on fd=-1 (placeholder — result fd not wired up at submission
 * time) exercises the linked-request setup/teardown and the SHUTDOWN
 * opcode path.
 * ------------------------------------------------------------------ */
static bool recipe_socket_shutdown_linked(struct iour_ctx *ctx,
					  bool *unsupported)
{
	struct io_uring_sqe sqes[2];
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_SOCKET;
	sqes[0].fd        = AF_INET;
	sqes[0].off       = SOCK_STREAM;
	sqes[0].user_data = 50;
	sqes[0].flags     = IOSQE_IO_LINK;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_SHUTDOWN;
	sqes[1].fd        = -1;
	sqes[1].len       = SHUT_RDWR;
	sqes[1].user_data = 51;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;

	r = iour_enter(ctx, 2, 1);
	if (r < 0) {
		if (errno == ENOSYS) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe 7: NOP chain with IOSQE_CQE_SKIP_SUCCESS
 *
 * Submit three NOPs where the middle one has IOSQE_CQE_SKIP_SUCCESS.
 * The kernel should post CQEs for the first and last but suppress the
 * middle one on success.  This exercises the CQE-skip accounting path
 * and its interaction with linked requests.
 * ------------------------------------------------------------------ */
static bool recipe_nop_cqe_skip(struct iour_ctx *ctx,
				bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[3];
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 60;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_NOP;
	sqes[1].flags     = IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS;
	sqes[1].user_data = 61;

	sqe_clear(&sqes[2]);
	sqes[2].opcode    = IORING_OP_NOP;
	sqes[2].user_data = 62;

	if (!iour_submit_sqes(ctx, sqes, 3))
		return false;

	r = iour_enter(ctx, 3, 2);
	if (r < 0)
		return false;

	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe 8: ASYNC_CANCEL on an in-flight op
 *
 * Submit a POLL_ADD that won't fire (eventfd stays at zero) so it
 * remains pending in the ring, then immediately cancel it via
 * IORING_OP_ASYNC_CANCEL targeting the same user_data.  This is the
 * canonical cancellation race that surfaces in io_uring CVEs involving
 * use-after-free on the request-completion path when a cancel races
 * the natural completion.
 * ------------------------------------------------------------------ */
static bool recipe_async_cancel(struct iour_ctx *ctx,
				bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[2];
	int evfd = -1;
	bool ok = false;
	int r;

	evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (evfd < 0)
		goto out;

	/* POLL_ADD that won't fire — stays pending. */
	sqe_clear(&sqes[0]);
	sqes[0].opcode        = IORING_OP_POLL_ADD;
	sqes[0].fd            = evfd;
	sqes[0].poll32_events = POLLIN;
	sqes[0].user_data     = 70;

	/* ASYNC_CANCEL targeting user_data=70. */
	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_ASYNC_CANCEL;
	sqes[1].addr      = 70;
	sqes[1].user_data = 71;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		goto out;

	iour_drain_cqes(ctx);
	ok = true;
out:
	if (evfd >= 0)
		close(evfd);
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 9: READ_FIXED with IORING_REGISTER_BUFFERS (registered fixed buffers)
 *
 * Register a page-sized buffer with the ring, then submit
 * IORING_OP_READ_FIXED targeting buffer index 0 against /dev/zero.
 * This exercises the registered-buffer fast path: the kernel skips the
 * per-syscall get_user_pages and reads directly into the pre-pinned
 * region.  Unregister before teardown to exercise the unpin path.
 * ------------------------------------------------------------------ */
static bool recipe_fixed_buffer_read(struct iour_ctx *ctx,
				     bool *unsupported __unused__)
{
	struct iovec iov;
	struct io_uring_sqe sqe;
	struct map *m = NULL;
	void *buf = NULL;
	size_t buf_sz = 0;
	int devzero = -1;
	bool registered = false;
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

	iov.iov_base = buf;
	iov.iov_len  = buf_sz;

	r = (int)syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_BUFFERS, &iov, 1);
	if (r < 0)
		goto out;
	registered = true;

	devzero = open("/dev/zero", O_RDONLY | O_CLOEXEC);
	if (devzero < 0)
		goto out;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_READ_FIXED;
	sqe.fd        = devzero;
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
	if (registered)
		(void)syscall(__NR_io_uring_register, ctx->fd,
			      IORING_UNREGISTER_BUFFERS, NULL, 0);
	if (devzero >= 0)
		close(devzero);
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
static bool recipe_write_read_fixed(struct iour_ctx *ctx,
				    bool *unsupported __unused__)
{
	struct io_uring_sqe sqes[2];
	struct iovec iov;
	struct map *m = NULL;
	int pfd[2] = { -1, -1 };
	void *buf = NULL;
	size_t buf_sz = 0;
	bool registered = false;
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

	iov.iov_base = buf;
	iov.iov_len  = buf_sz;

	r = (int)syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_BUFFERS, &iov, 1);
	if (r < 0)
		goto out;
	registered = true;

	if (pipe(pfd) < 0)
		goto out;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_WRITE_FIXED;
	sqes[0].fd        = pfd[1];
	sqes[0].addr      = (__u64)(uintptr_t)buf;
	sqes[0].len       = 64;
	sqes[0].buf_index = 0;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 90;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_READ_FIXED;
	sqes[1].fd        = pfd[0];
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
	if (registered)
		(void)syscall(__NR_io_uring_register, ctx->fd,
			      IORING_UNREGISTER_BUFFERS, NULL, 0);
	if (pfd[0] >= 0) close(pfd[0]);
	if (pfd[1] >= 0) close(pfd[1]);
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
static bool recipe_provide_buffers(struct iour_ctx *ctx,
				   bool *unsupported __unused__)
{
#define PBUF_GROUP_ID	1
#define PBUF_COUNT	4
#define PBUF_BUF_SIZE	256

	struct io_uring_sqe sqe;
	char *bufs = NULL;
	int sv[2] = { -1, -1 };
	bool provided = false;
	bool ok = false;
	int r;

	bufs = malloc((size_t)PBUF_COUNT * PBUF_BUF_SIZE);
	if (!bufs)
		goto out;
	memset(bufs, 0, (size_t)PBUF_COUNT * PBUF_BUF_SIZE);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
		goto out;

	/* PROVIDE_BUFFERS: addr=start, len=buf_size, fd=count, off=start_bid. */
	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_PROVIDE_BUFFERS;
	sqe.addr      = (__u64)(uintptr_t)bufs;
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
	provided = true;

	{
		const char msg[] = "recipe";
		ssize_t w __unused__ = write(sv[0], msg, sizeof(msg));
	}

	/* RECV with IOSQE_BUFFER_SELECT — kernel picks buffer from group. */
	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_RECV;
	sqe.fd        = sv[1];
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
	provided = false;

	ok = true;
out:
	if (provided) {
		struct io_uring_sqe s;

		sqe_clear(&s);
		s.opcode    = IORING_OP_REMOVE_BUFFERS;
		s.fd        = PBUF_COUNT;
		s.buf_group = PBUF_GROUP_ID;
		s.user_data = 103;
		if (iour_submit_sqes(ctx, &s, 1))
			iour_enter(ctx, 1, 0);
		iour_drain_cqes(ctx);
	}
	if (sv[0] >= 0) close(sv[0]);
	if (sv[1] >= 0) close(sv[1]);
	free(bufs);
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

static bool recipe_msg_ring(struct iour_ctx *ctx, bool *unsupported)
{
	struct iour_ctx dst;
	struct io_uring_sqe sqe;
	bool dst_ok = false;
	bool ok = false;
	int r;

	if (!iour_setup(&dst, 8))
		goto out;
	dst_ok = true;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_MSG_RING;
	sqe.fd        = dst.fd;
	sqe.len       = 0;
	sqe.off       = 0xdeadbeefULL;
	sqe.user_data = 110;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}

	iour_drain_cqes(ctx);
	iour_drain_cqes(&dst);
	ok = true;
out:
	if (dst_ok)
		iour_teardown(&dst);
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
static bool recipe_statx_fixed_file(struct iour_ctx *ctx,
				    bool *unsupported __unused__)
{
	struct io_uring_sqe sqe;
	struct statx stx;
	int fds[1] = { -1 };
	int devnull = -1;
	bool registered = false;
	bool ok = false;
	int r;
	static const char empty[] = "";

	devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (devnull < 0)
		goto out;

	fds[0] = devnull;
	r = (int)syscall(__NR_io_uring_register, ctx->fd,
			 IORING_REGISTER_FILES, fds, 1);
	if (r < 0)
		goto out;
	registered = true;

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
	if (registered)
		(void)syscall(__NR_io_uring_register, ctx->fd,
			      IORING_UNREGISTER_FILES, NULL, 0);
	if (devnull >= 0)
		close(devnull);
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 14: FUTEX_WAIT + FUTEX_WAKE via io_uring
 *
 * Draw a shared-anon region from the parent's inherited mapping pool,
 * submit IORING_OP_FUTEX_WAIT with an expected value that doesn't match
 * (fast EAGAIN path), then IORING_OP_FUTEX_WAKE on the same address.
 * Exercises the io_uring futex dispatch path added in Linux 6.7.  First
 * ENOSYS latches the recipe off.
 * ------------------------------------------------------------------ */
#ifndef IORING_OP_FUTEX_WAIT
#define IORING_OP_FUTEX_WAIT	46
#define IORING_OP_FUTEX_WAKE	47
#endif

static bool recipe_futex_wait_wake(struct iour_ctx *ctx, bool *unsupported)
{
	struct io_uring_sqe sqes[2];
	struct map *m = NULL;
	uint32_t *addr = NULL;
	bool ok = false;
	int r;

	/* Draw the futex backing storage from the parent's inherited
	 * mapping pool.  Sibling iouring children draw from the same pool,
	 * so multiple rings will sometimes target the same futex word —
	 * that overlap is the CV.4 target, exercising io_uring's futex
	 * dispatch and the kernel's shared-key hash bucket against
	 * cross-sibling waiters and wakers on identical keys.
	 *
	 * The pool owns the mapping: do NOT munmap on cleanup.
	 *
	 * Filter the pool draw on PROT_READ | PROT_WRITE: the recipe stores
	 * to the value word before submission and the kernel reads it during
	 * the cmpxchg in the FUTEX_WAIT op handler.  PROT_READ-only or
	 * PROT_NONE pool entries would SEGV on the value-word store before
	 * the SQE is ever submitted. */
	m = get_map_with_prot(PROT_READ | PROT_WRITE);
	if (m == NULL)
		goto out;
	addr = (uint32_t *)m->ptr;

	*addr = 0;

	/* FUTEX_WAIT with val=1 — mismatches *addr=0, returns EAGAIN. */
	sqe_clear(&sqes[0]);
	sqes[0].opcode      = IORING_OP_FUTEX_WAIT;
	sqes[0].fd          = FUTEX_BITSET_MATCH_ANY;
	sqes[0].addr        = (__u64)(uintptr_t)addr;
	sqes[0].addr2       = 1;
	sqes[0].futex_flags = FUTEX_PRIVATE_FLAG;
	sqes[0].user_data   = 130;

	sqe_clear(&sqes[1]);
	sqes[1].opcode      = IORING_OP_FUTEX_WAKE;
	sqes[1].fd          = FUTEX_BITSET_MATCH_ANY;
	sqes[1].addr        = (__u64)(uintptr_t)addr;
	sqes[1].off         = INT_MAX;
	sqes[1].futex_flags = FUTEX_PRIVATE_FLAG;
	sqes[1].user_data   = 131;

	if (!iour_submit_sqes(ctx, sqes, 2))
		goto out;

	r = iour_enter(ctx, 2, 1);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}

	iour_drain_cqes(ctx);
	ok = true;
out:
	return ok;
}

/* ------------------------------------------------------------------ *
 * Recipe 15: EPOLL_WAIT via io_uring
 *
 * Create an epoll fd with an eventfd registered, then submit
 * IORING_OP_EPOLL_WAIT with timeout_ms=0.  Nothing is ready so the
 * wait returns immediately, but the kernel walks the epoll wait-list
 * setup and teardown path inside io_uring's implementation.  Added in
 * Linux 6.15; first ENOSYS/EINVAL latches the recipe off.
 * ------------------------------------------------------------------ */
#ifndef IORING_OP_EPOLL_WAIT
#define IORING_OP_EPOLL_WAIT	59
#endif

static bool recipe_epoll_wait(struct iour_ctx *ctx, bool *unsupported)
{
	struct io_uring_sqe sqe;
	struct epoll_event ev;
	struct epoll_event evs[4];
	int epfd = -1;
	int evfd = -1;
	bool ok = false;
	int r;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		goto out;

	evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (evfd < 0)
		goto out;

	memset(&ev, 0, sizeof(ev));
	ev.events  = EPOLLIN;
	ev.data.fd = evfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, evfd, &ev) < 0)
		goto out;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_EPOLL_WAIT;
	sqe.fd        = epfd;
	sqe.addr      = (__u64)(uintptr_t)evs;
	sqe.len       = ARRAY_SIZE(evs);
	sqe.off       = 0;
	sqe.user_data = 140;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		goto out;

	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}

	iour_drain_cqes(ctx);
	ok = true;
out:
	if (evfd >= 0) close(evfd);
	if (epfd >= 0) close(epfd);
	return ok;
}

static const struct iour_recipe catalog[] = {
	{ "nop_chain",              recipe_nop_chain              },
	{ "timeout_drain",          recipe_timeout_drain          },
	{ "poll_multishot",         recipe_poll_multishot         },
	{ "send_recv_linked",       recipe_send_recv_linked       },
	{ "openat_close_linked",    recipe_openat_close_linked    },
	{ "socket_shutdown_linked", recipe_socket_shutdown_linked },
	{ "nop_cqe_skip",           recipe_nop_cqe_skip           },
	{ "async_cancel",           recipe_async_cancel           },
	{ "fixed_buffer_read",      recipe_fixed_buffer_read      },
	{ "write_read_fixed",       recipe_write_read_fixed       },
	{ "provide_buffers",        recipe_provide_buffers        },
	{ "msg_ring",               recipe_msg_ring               },
	{ "statx_fixed_file",       recipe_statx_fixed_file       },
	{ "futex_wait_wake",        recipe_futex_wait_wake        },
	{ "epoll_wait",             recipe_epoll_wait             },
};

_Static_assert(ARRAY_SIZE(catalog) <= MAX_IOURING_RECIPES,
	       "iouring recipe catalog outgrew MAX_IOURING_RECIPES; bump it");

bool iouring_recipes(struct childdata *child __unused__)
{
	struct iour_ctx ctx;
	const struct iour_recipe *r;
	unsigned int idx;
	unsigned int tries;
	bool unsupported = false;
	bool ok;

	__atomic_add_fetch(&shm->stats.iouring_recipes_runs, 1,
			   __ATOMIC_RELAXED);

	/* Latch: once we know io_uring_setup returns ENOSYS, stop trying. */
	if (__atomic_load_n(&shm->iouring_enosys, __ATOMIC_RELAXED))
		return true;

	/* Pick a recipe that hasn't been disabled. */
	for (tries = 0; tries < 8; tries++) {
		idx = (unsigned int)rand() % (unsigned int)ARRAY_SIZE(catalog);
		if (!__atomic_load_n(&shm->iouring_recipe_disabled[idx],
				     __ATOMIC_RELAXED))
			break;
	}
	if (tries == 8)
		return true;

	r = &catalog[idx];

	output(1, "iouring-recipe: running %s\n", r->name);

	if (!iour_setup(&ctx, 16)) {
		if (errno == ENOSYS)
			__atomic_store_n(&shm->iouring_enosys, true,
					 __ATOMIC_RELAXED);
		return true;
	}

	ok = r->run(&ctx, &unsupported);

	iour_teardown(&ctx);

	if (unsupported)
		__atomic_store_n(&shm->iouring_recipe_disabled[idx], true,
				 __ATOMIC_RELAXED);

	if (ok) {
		__atomic_add_fetch(&shm->stats.iouring_recipes_completed, 1,
				   __ATOMIC_RELAXED);
		__atomic_add_fetch(
			&shm->stats.iouring_recipe_completed_per[idx], 1,
			__ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.iouring_recipes_partial, 1,
				   __ATOMIC_RELAXED);
	}

	return true;
}

void iouring_recipes_dump_stats(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(catalog); i++) {
		unsigned long n = __atomic_load_n(
			&shm->stats.iouring_recipe_completed_per[i],
			__ATOMIC_RELAXED);
		bool disabled = __atomic_load_n(
			&shm->iouring_recipe_disabled[i],
			__ATOMIC_RELAXED);

		if (n == 0 && !disabled)
			continue;

		output(0, "  %-24s %lu%s\n",
			catalog[i].name, n,
			disabled ? " (disabled — kernel feature absent)" : "");
	}
}
