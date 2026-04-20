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
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <linux/io_uring.h>

#include "arch.h"
#include "child.h"
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
	ctx->fd = (int)syscall(__NR_io_uring_setup, entries, &p);
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

static const struct iour_recipe catalog[] = {
	{ "nop_chain",              recipe_nop_chain              },
	{ "timeout_drain",          recipe_timeout_drain          },
	{ "poll_multishot",         recipe_poll_multishot         },
	{ "send_recv_linked",       recipe_send_recv_linked       },
	{ "openat_close_linked",    recipe_openat_close_linked    },
	{ "socket_shutdown_linked", recipe_socket_shutdown_linked },
	{ "nop_cqe_skip",           recipe_nop_cqe_skip           },
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
