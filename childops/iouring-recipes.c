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
#include <netinet/in.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
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
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <linux/io_uring.h>

#include "compat.h"
#include "pids.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC	0x0001U
#endif

/* Local mirror of struct open_how — avoid a build-time dependency on
 * a kernel header that older distributions ship without. */
struct iour_open_how {
	__u64	flags;
	__u64	mode;
	__u64	resolve;
};


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

/*
 * Per-iteration recipe resources.  Recipes may allocate fds, pipes,
 * sockets, malloc'd buffers, an inner io_uring ring, or io_uring-side
 * registrations (registered buffers / files / provided buffers).  The
 * pool-race siglongjmp in iouring_recipes() unwinds straight to the
 * wrap's setjmp landing pad, skipping the recipe's own cleanup; this
 * struct lives in the wrap's stack frame so it survives the longjmp,
 * and iour_recipe_state_cleanup() releases every populated field.
 *
 * Sentinels: -1 for fds, NULL for pointers, false for bools.  The
 * cleanup is idempotent — recipes may clear fields after a deliberate
 * teardown mid-execution (e.g. recipe_provide_buffers' REMOVE_BUFFERS),
 * and the wrap calls cleanup unconditionally on both the success and
 * abort paths.
 */
struct iour_recipe_state {
	struct iour_ctx	*ctx;		/* outer ring; convenience handle */

	int		evfd;
	int		sock[2];
	int		pipefd[2];
	int		pipefd2[2];	/* second pipe pair (SPLICE/TEE) */
	int		open_fd;	/* /dev/null, /dev/zero, etc. */
	int		memfd;		/* memfd_create-backed regular file */
	int		epoll_fd;
	void		*malloc_buf;

	struct iour_ctx	inner;		/* recipe_msg_ring destination */
	bool		inner_active;

	bool		registered_buf;	  /* IORING_REGISTER_BUFFERS active */
	bool		registered_files; /* IORING_REGISTER_FILES active */

	bool		provided_buf_active;
	unsigned int	provided_buf_group_id;
	unsigned int	provided_buf_count;
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

static void iour_recipe_state_init(struct iour_recipe_state *s,
				   struct iour_ctx *ctx)
{
	memset(s, 0, sizeof(*s));
	s->ctx        = ctx;
	s->evfd       = -1;
	s->sock[0]    = -1;
	s->sock[1]    = -1;
	s->pipefd[0]  = -1;
	s->pipefd[1]  = -1;
	s->pipefd2[0] = -1;
	s->pipefd2[1] = -1;
	s->open_fd    = -1;
	s->memfd      = -1;
	s->epoll_fd   = -1;
}

/*
 * Tear down every populated recipe resource.  Idempotent: each branch
 * checks the field's sentinel and clears it after release, so the caller
 * may invoke this on both the success path (after the recipe has cleared
 * the fields it deliberately tore down) and the siglongjmp landing path
 * (where fields hold whatever the aborted recipe had set).
 *
 * Order matters: io_uring registrations and the inner ring must be torn
 * down before the outer ring (which the wrap closes after this returns),
 * and provided-buffer REMOVE_BUFFERS must run before UNREGISTER because
 * it submits an SQE on the outer ring.
 */
static void iour_recipe_state_cleanup(struct iour_recipe_state *s)
{
	if (s->provided_buf_active) {
		struct io_uring_sqe sqe;

		sqe_clear(&sqe);
		sqe.opcode    = IORING_OP_REMOVE_BUFFERS;
		sqe.fd        = s->provided_buf_count;
		sqe.buf_group = s->provided_buf_group_id;
		sqe.user_data = 999;
		if (iour_submit_sqes(s->ctx, &sqe, 1))
			(void)iour_enter(s->ctx, 1, 0);
		iour_drain_cqes(s->ctx);
		s->provided_buf_active = false;
	}
	if (s->registered_buf) {
		(void)syscall(__NR_io_uring_register, s->ctx->fd,
			      IORING_UNREGISTER_BUFFERS, NULL, 0);
		s->registered_buf = false;
	}
	if (s->registered_files) {
		(void)syscall(__NR_io_uring_register, s->ctx->fd,
			      IORING_UNREGISTER_FILES, NULL, 0);
		s->registered_files = false;
	}
	if (s->inner_active) {
		iour_teardown(&s->inner);
		s->inner_active = false;
	}
	if (s->evfd >= 0) {
		close(s->evfd);
		s->evfd = -1;
	}
	if (s->sock[0] >= 0) {
		close(s->sock[0]);
		s->sock[0] = -1;
	}
	if (s->sock[1] >= 0) {
		close(s->sock[1]);
		s->sock[1] = -1;
	}
	if (s->pipefd[0] >= 0) {
		close(s->pipefd[0]);
		s->pipefd[0] = -1;
	}
	if (s->pipefd[1] >= 0) {
		close(s->pipefd[1]);
		s->pipefd[1] = -1;
	}
	if (s->pipefd2[0] >= 0) {
		close(s->pipefd2[0]);
		s->pipefd2[0] = -1;
	}
	if (s->pipefd2[1] >= 0) {
		close(s->pipefd2[1]);
		s->pipefd2[1] = -1;
	}
	if (s->open_fd >= 0) {
		close(s->open_fd);
		s->open_fd = -1;
	}
	if (s->memfd >= 0) {
		close(s->memfd);
		s->memfd = -1;
	}
	if (s->epoll_fd >= 0) {
		close(s->epoll_fd);
		s->epoll_fd = -1;
	}
	if (s->malloc_buf) {
		free(s->malloc_buf);
		s->malloc_buf = NULL;
	}
}

/*
 * A discoverable recipe sets *unsupported = true when it first encounters
 * ENOSYS or a missing kernel feature.  The dispatcher latches the recipe off
 * in shm so siblings stop probing.
 */
struct iour_recipe {
	const char *name;
	bool (*run)(struct iour_recipe_state *s, bool *unsupported);
};

/* Pool-race fault guard.  See childops/memory-pressure.c for the full
 * rationale.  The wrap below catches a sibling-driven UAF on a pool-
 * drawn buffer used inside r->run().  Only 3 of the 15 catalog recipes
 * draw from the parent's mapping pool (recipe_fixed_buffer_read,
 * recipe_write_read_fixed, recipe_futex_wait_wake); the other 12 do
 * not touch pool memory at all.
 *
 * The handler siglongjmps only when (a) the fault is a real kernel
 * fault (si_code > 0) and (b) si_addr is inside the pool mapping
 * range that the dispatched recipe drew.  The 3 pool-drawing recipes
 * publish their drawn range into the file-scope statics below right
 * after get_map_with_prot() returns; non-pool-drawing recipes never
 * touch the statics, so the range stays at 0..0 (set by the wrap
 * site before sigsetjmp) and every si_addr falls outside.  An
 * outside-range fault — including any fault from a non-pool recipe —
 * restores SIG_DFL and re-raises so child_fault_handler diagnoses +
 * exits and the per-pid bug log path is preserved.
 *
 * Volatile-qualified for the same reason as the equivalent statics
 * in memory-pressure: stop the compiler hoisting/coalescing reads
 * across the asynchronous handler entry.  Aligned word reads are
 * atomic on supported arches; the writes complete before sigaction
 * installs the handler so ordering is provided by the kernel-side
 * sigaction barrier (or, for the per-recipe writes, by the fact
 * that the handler can only be entered as a result of a fault
 * delivered to this thread after the writes have committed). */
static sigjmp_buf iouring_recipes_pool_race_jmp;
static volatile uintptr_t iouring_recipes_pool_race_addr_low;
static volatile uintptr_t iouring_recipes_pool_race_addr_high;

static void iouring_recipes_pool_race_handler(int sig, siginfo_t *info,
					      void *ctx)
{
	uintptr_t fault_addr;

	(void)ctx;
	if (info->si_code <= 0 && info->si_pid != mypid()) {
		/* Sibling-spoofed — kernel consumed the signal already. */
		return;
	}
	if (info->si_code <= 0) {
		/* Self-sent (glibc abort etc.) — restore default and
		 * re-raise so child_fault_handler diagnoses + exits.
		 * siglongjmp here would orphan the allocator lock. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}

	fault_addr = (uintptr_t)info->si_addr;
	if (fault_addr < iouring_recipes_pool_race_addr_low ||
	    fault_addr >= iouring_recipes_pool_race_addr_high) {
		/* Real kernel fault but si_addr is outside the drawn
		 * pool range (including the range-empty case for the 12
		 * non-pool-drawing recipes) — not the race we're guarding
		 * against.  Restore default and re-raise so
		 * child_fault_handler diagnoses + exits and the bug log
		 * path is preserved. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(iouring_recipes_pool_race_jmp, 1);
}

/* ------------------------------------------------------------------ *
 * Recipe 1: NOP chain (sanity + linked-SQE chain dispatch)
 *
 * Submit three IORING_OP_NOP SQEs where the first two carry
 * IOSQE_IO_LINK so they execute as a linked sequence.  NOP has no
 * side effects; the target here is the chain-dispatch logic: the kernel
 * must propagate the linked state through two members before posting
 * the final unlinked completion.
 * ------------------------------------------------------------------ */
static bool recipe_nop_chain(struct iour_recipe_state *s,
			      bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
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
static bool recipe_timeout_drain(struct iour_recipe_state *s,
				 bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
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

static bool recipe_poll_multishot(struct iour_recipe_state *s,
				  bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	bool ok = false;
	int r;

	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		goto out;

	/* POLL_ADD with IORING_POLL_ADD_MULTI (multi-shot). */
	sqe_clear(&sqes[0]);
	sqes[0].opcode        = IORING_OP_POLL_ADD;
	sqes[0].fd            = s->evfd;
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
static bool recipe_send_recv_linked(struct iour_recipe_state *s,
				    bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	char buf[32];
	bool ok = false;
	int r;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, s->sock) < 0)
		goto out;

	memset(buf, 's', sizeof(buf));

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_SEND;
	sqes[0].fd        = s->sock[0];
	sqes[0].addr      = (__u64)(uintptr_t)buf;
	sqes[0].len       = sizeof(buf);
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 30;

	sqe_clear(&sqes[1]);
	sqes[1].opcode    = IORING_OP_RECV;
	sqes[1].fd        = s->sock[1];
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
static bool recipe_openat_close_linked(struct iour_recipe_state *s,
				       bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
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
static bool recipe_socket_shutdown_linked(struct iour_recipe_state *s,
					  bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
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
static bool recipe_nop_cqe_skip(struct iour_recipe_state *s,
				bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
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
static bool recipe_async_cancel(struct iour_recipe_state *s,
				bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	bool ok = false;
	int r;

	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		goto out;

	/* POLL_ADD that won't fire — stays pending. */
	sqe_clear(&sqes[0]);
	sqes[0].opcode        = IORING_OP_POLL_ADD;
	sqes[0].fd            = s->evfd;
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
static bool recipe_fixed_buffer_read(struct iour_recipe_state *s,
				     bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
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

	r = (int)syscall(__NR_io_uring_register, ctx->fd,
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
static bool recipe_write_read_fixed(struct iour_recipe_state *s,
				    bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
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

	r = (int)syscall(__NR_io_uring_register, ctx->fd,
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
static bool recipe_provide_buffers(struct iour_recipe_state *s,
				   bool *unsupported __unused__)
{
#define PBUF_GROUP_ID	1
#define PBUF_COUNT	4
#define PBUF_BUF_SIZE	256

	struct iour_ctx *ctx = s->ctx;
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

static bool recipe_msg_ring(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	bool ok = false;
	int r;

	if (!iour_setup(&s->inner, 8))
		goto out;
	s->inner_active = true;

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
		if (errno == ENOSYS || errno == EINVAL) {
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
static bool recipe_statx_fixed_file(struct iour_recipe_state *s,
				    bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
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
	r = (int)syscall(__NR_io_uring_register, ctx->fd,
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
 * Recipe 14: FUTEX_WAIT + FUTEX_WAKE via io_uring
 *
 * Draw a shared-anon region from the parent's inherited mapping pool,
 * submit IORING_OP_FUTEX_WAIT with an expected value that doesn't match
 * (fast EAGAIN path), then IORING_OP_FUTEX_WAKE on the same address.
 * Exercises the io_uring futex dispatch path added in Linux 6.7.  First
 * ENOSYS latches the recipe off.
 * ------------------------------------------------------------------ */
#ifndef TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE
static bool recipe_futex_wait_wake(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
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

	/* Publish drawn pool range — see recipe_fixed_buffer_read for the
	 * full rationale.  The value-word store below is the first
	 * userspace deref of the pool entry and the most likely fault
	 * site if a sibling has unmapped between the draw and now. */
	iouring_recipes_pool_race_addr_low  = (uintptr_t)m->ptr;
	iouring_recipes_pool_race_addr_high = (uintptr_t)m->ptr + m->size;

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
#endif /* TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE */

/* ------------------------------------------------------------------ *
 * Recipe 15: EPOLL_WAIT via io_uring
 *
 * Create an epoll fd with an eventfd registered, then submit
 * IORING_OP_EPOLL_WAIT with timeout_ms=0.  Nothing is ready so the
 * wait returns immediately, but the kernel walks the epoll wait-list
 * setup and teardown path inside io_uring's implementation.  Added in
 * Linux 6.15; first ENOSYS/EINVAL latches the recipe off.
 * ------------------------------------------------------------------ */
static bool recipe_epoll_wait(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct epoll_event ev;
	struct epoll_event evs[4];
	bool ok = false;
	int r;

	s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (s->epoll_fd < 0)
		goto out;

	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		goto out;

	memset(&ev, 0, sizeof(ev));
	ev.events  = EPOLLIN;
	ev.data.fd = s->evfd;
	if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->evfd, &ev) < 0)
		goto out;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_EPOLL_WAIT;
	sqe.fd        = s->epoll_fd;
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
	return ok;
}

/* ================================================================== *
 * Per-opcode breadth recipes
 *
 * One single-shot recipe per IORING_OP_* that the chained recipes above
 * don't already cover.  The per-op SQE field validators (prep) and
 * issue paths in io_uring/opdef.c are reached even when the underlying
 * syscall returns -ENOENT/-EBADF/-EINVAL/-ECHILD on synthetic args, so
 * recipes deliberately keep arguments simple — the kernel surface is
 * the validator state machine, not the data.
 * ================================================================== */

/* ------------------------------------------------------------------ *
 * Recipe: SENDMSG over socketpair
 * ------------------------------------------------------------------ */
static bool recipe_sendmsg(struct iour_recipe_state *s,
			   bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct msghdr msg;
	struct iovec iov;
	char buf[32];
	int r;

	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, s->sock) < 0)
		return false;

	memset(buf, 'm', sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len  = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_SENDMSG;
	sqe.fd        = s->sock[0];
	sqe.addr      = (__u64)(uintptr_t)&msg;
	sqe.msg_flags = MSG_DONTWAIT;
	sqe.user_data = 200;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: RECVMSG over socketpair (with primer write)
 * ------------------------------------------------------------------ */
static bool recipe_recvmsg(struct iour_recipe_state *s,
			   bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct msghdr msg;
	struct iovec iov;
	char buf[32];
	int r;

	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, s->sock) < 0)
		return false;

	{
		const char primer[] = "recvmsg";
		ssize_t w __unused__ = write(s->sock[0], primer, sizeof(primer));
	}

	iov.iov_base = buf;
	iov.iov_len  = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_RECVMSG;
	sqe.fd        = s->sock[1];
	sqe.addr      = (__u64)(uintptr_t)&msg;
	sqe.msg_flags = MSG_DONTWAIT;
	sqe.user_data = 210;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: ACCEPT on a non-listening socketpair endpoint
 *
 * The socketpair fd isn't a listener, so ops->accept() returns
 * synchronously — the io_uring accept prep + issue dispatch still runs.
 * ------------------------------------------------------------------ */
static bool recipe_accept(struct iour_recipe_state *s,
			  bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	int r;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, s->sock) < 0)
		return false;

	memset(&ss, 0, sizeof(ss));

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_ACCEPT;
	sqe.fd           = s->sock[0];
	sqe.addr         = (__u64)(uintptr_t)&ss;
	sqe.addr2        = (__u64)(uintptr_t)&slen;
	sqe.accept_flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
	sqe.user_data    = 220;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: CONNECT to 127.0.0.1:1 (likely ECONNREFUSED)
 * ------------------------------------------------------------------ */
static bool recipe_connect(struct iour_recipe_state *s,
			   bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_in sin;
	int r;

	s->sock[0] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			    0);
	if (s->sock[0] < 0)
		return false;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(1);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_CONNECT;
	sqe.fd        = s->sock[0];
	sqe.addr      = (__u64)(uintptr_t)&sin;
	sqe.off       = sizeof(sin);
	sqe.user_data = 230;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: BIND to a fresh AF_INET ephemeral port
 *
 * The kernel reads sockaddr length from sqe->addr_len (the u16 sharing
 * the splice_fd_in union) for IORING_OP_BIND.  Port 0 → kernel auto-
 * assigns; loopback is universally available.
 * ------------------------------------------------------------------ */
#ifndef TRINITY_COMPAT_BACKFILLED_BIND
static bool recipe_bind(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_in sin;
	int r;

	s->sock[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s->sock[0] < 0)
		return false;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_BIND;
	sqe.fd        = s->sock[0];
	sqe.addr      = (__u64)(uintptr_t)&sin;
	sqe.addr_len  = sizeof(sin);
	sqe.user_data = 240;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}
	iour_drain_cqes(ctx);
	return true;
}
#endif /* TRINITY_COMPAT_BACKFILLED_BIND */

/* ------------------------------------------------------------------ *
 * Recipe: LISTEN on a freshly-bound TCP socket
 * ------------------------------------------------------------------ */
static bool recipe_listen(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct sockaddr_in sin;
	int r;

	s->sock[0] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s->sock[0] < 0)
		return false;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s->sock[0], (struct sockaddr *)&sin, sizeof(sin)) < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_LISTEN;
	sqe.fd        = s->sock[0];
	sqe.len       = 8;
	sqe.user_data = 250;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
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
 * memfd helper used by the regular-file family below.
 * ------------------------------------------------------------------ */
static int iour_make_memfd(void)
{
	int fd = (int)syscall(SYS_memfd_create, "trinity-iour", MFD_CLOEXEC);

	if (fd < 0)
		return -1;
	if (ftruncate(fd, 4096) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* ------------------------------------------------------------------ *
 * Recipe: FSYNC on a memfd
 * ------------------------------------------------------------------ */
static bool recipe_fsync(struct iour_recipe_state *s,
			 bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_FSYNC;
	sqe.fd          = s->memfd;
	sqe.fsync_flags = 0;
	sqe.user_data   = 260;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: SYNC_FILE_RANGE on a memfd
 * ------------------------------------------------------------------ */
static bool recipe_sync_file_range(struct iour_recipe_state *s,
				   bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode           = IORING_OP_SYNC_FILE_RANGE;
	sqe.fd               = s->memfd;
	sqe.off              = 0;
	sqe.len              = 4096;
	sqe.sync_range_flags = 0;
	sqe.user_data        = 270;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: READV from /dev/zero into a stack iovec
 * ------------------------------------------------------------------ */
static bool recipe_readv(struct iour_recipe_state *s,
			 bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct iovec iov[2];
	char buf1[64], buf2[64];
	int r;

	s->open_fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
	if (s->open_fd < 0)
		return false;

	iov[0].iov_base = buf1;
	iov[0].iov_len  = sizeof(buf1);
	iov[1].iov_base = buf2;
	iov[1].iov_len  = sizeof(buf2);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_READV;
	sqe.fd        = s->open_fd;
	sqe.addr      = (__u64)(uintptr_t)iov;
	sqe.len       = 2;
	sqe.off       = 0;
	sqe.user_data = 280;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: WRITEV to a memfd via two iovecs
 * ------------------------------------------------------------------ */
static bool recipe_writev(struct iour_recipe_state *s,
			  bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct iovec iov[2];
	char buf1[32], buf2[32];
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	memset(buf1, 'a', sizeof(buf1));
	memset(buf2, 'b', sizeof(buf2));
	iov[0].iov_base = buf1;
	iov[0].iov_len  = sizeof(buf1);
	iov[1].iov_base = buf2;
	iov[1].iov_len  = sizeof(buf2);

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_WRITEV;
	sqe.fd        = s->memfd;
	sqe.addr      = (__u64)(uintptr_t)iov;
	sqe.len       = 2;
	sqe.off       = 0;
	sqe.user_data = 290;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: FALLOCATE on a memfd
 *
 * SQE layout: sqe->fd, sqe->off=offset, sqe->addr=length, sqe->len=mode.
 * ------------------------------------------------------------------ */
static bool recipe_fallocate(struct iour_recipe_state *s,
			     bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_FALLOCATE;
	sqe.fd        = s->memfd;
	sqe.off       = 0;
	sqe.addr      = 8192;
	sqe.len       = 0;
	sqe.user_data = 300;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: FTRUNCATE on a memfd
 *
 * SQE layout: sqe->fd, sqe->off=length.
 * ------------------------------------------------------------------ */
static bool recipe_ftruncate(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_FTRUNCATE;
	sqe.fd        = s->memfd;
	sqe.off       = 2048;
	sqe.user_data = 310;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
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
 * Recipe: FADVISE on a memfd
 *
 * SQE layout: sqe->fd, sqe->off=offset, sqe->addr=len, sqe->fadvise_advice.
 * ------------------------------------------------------------------ */
static bool recipe_fadvise(struct iour_recipe_state *s,
			   bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode         = IORING_OP_FADVISE;
	sqe.fd             = s->memfd;
	sqe.off            = 0;
	sqe.addr           = 4096;
	sqe.fadvise_advice = POSIX_FADV_WILLNEED;
	sqe.user_data      = 320;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: READ_MULTISHOT on a pipe with provided buffers + cancel
 *
 * READ_MULTISHOT requires IOSQE_BUFFER_SELECT and a buf_group containing
 * at least one buffer — provide one, arm the multishot, then cancel it
 * synchronously to drain the in-flight request before teardown.
 * ------------------------------------------------------------------ */
static bool recipe_read_multishot(struct iour_recipe_state *s,
				  bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;
#define READMS_GROUP	7
#define READMS_COUNT	2
#define READMS_SIZE	256

	s->malloc_buf = malloc((size_t)READMS_COUNT * READMS_SIZE);
	if (!s->malloc_buf)
		return false;
	memset(s->malloc_buf, 0, (size_t)READMS_COUNT * READMS_SIZE);

	if (pipe(s->pipefd) < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_PROVIDE_BUFFERS;
	sqe.addr      = (__u64)(uintptr_t)s->malloc_buf;
	sqe.len       = READMS_SIZE;
	sqe.fd        = READMS_COUNT;
	sqe.off       = 0;
	sqe.buf_group = READMS_GROUP;
	sqe.user_data = 330;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	if (iour_enter(ctx, 1, 1) < 0)
		return false;
	iour_drain_cqes(ctx);
	s->provided_buf_active   = true;
	s->provided_buf_group_id = READMS_GROUP;
	s->provided_buf_count    = READMS_COUNT;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_READ_MULTISHOT;
	sqe.fd        = s->pipefd[0];
	sqe.flags     = IOSQE_BUFFER_SELECT;
	sqe.buf_group = READMS_GROUP;
	sqe.user_data = 331;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 0);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.iouring_recipes_enosys,
					   1, __ATOMIC_RELAXED);
		}
		return false;
	}

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_ASYNC_CANCEL;
	sqe.addr      = 331;
	sqe.user_data = 332;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	if (iour_enter(ctx, 1, 1) < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;

#undef READMS_GROUP
#undef READMS_COUNT
#undef READMS_SIZE
}

/* ------------------------------------------------------------------ *
 * Recipe: OPENAT2 with a struct open_how (likely ENOENT)
 * ------------------------------------------------------------------ */
static bool recipe_openat2(struct iour_recipe_state *s,
			   bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct iour_open_how how;
	static const char path[] = "/dev/null";
	int r;

	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_OPENAT2;
	sqe.fd        = AT_FDCWD;
	sqe.addr      = (__u64)(uintptr_t)path;
	sqe.addr2     = (__u64)(uintptr_t)&how;
	sqe.len       = sizeof(how);
	sqe.user_data = 340;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: EPOLL_CTL — add an eventfd to an epoll set via the ring
 *
 * SQE layout: sqe->fd=epfd, sqe->len=op, sqe->off=target fd,
 *             sqe->addr=epoll_event*.
 * ------------------------------------------------------------------ */
static bool recipe_epoll_ctl(struct iour_recipe_state *s,
			     bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct epoll_event ev;
	int r;

	s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (s->epoll_fd < 0)
		return false;
	s->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (s->evfd < 0)
		return false;

	memset(&ev, 0, sizeof(ev));
	ev.events  = EPOLLIN;
	ev.data.fd = s->evfd;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_EPOLL_CTL;
	sqe.fd        = s->epoll_fd;
	sqe.len       = EPOLL_CTL_ADD;
	sqe.off       = s->evfd;
	sqe.addr      = (__u64)(uintptr_t)&ev;
	sqe.user_data = 350;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: SPLICE between two pipes (with primer write)
 * ------------------------------------------------------------------ */
static bool recipe_splice(struct iour_recipe_state *s,
			  bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	if (pipe(s->pipefd) < 0)
		return false;
	if (pipe(s->pipefd2) < 0)
		return false;

	{
		const char primer[64] = { 's', 'p', 'l', 'i', 'c', 'e' };
		ssize_t w __unused__ = write(s->pipefd[1], primer,
					     sizeof(primer));
	}

	sqe_clear(&sqe);
	sqe.opcode        = IORING_OP_SPLICE;
	sqe.fd            = s->pipefd2[1];	/* out */
	sqe.splice_fd_in  = s->pipefd[0];	/* in */
	sqe.splice_off_in = (__u64)-1;
	sqe.off           = (__u64)-1;
	sqe.len           = 64;
	sqe.splice_flags  = 0;
	sqe.user_data     = 360;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: TEE between two pipes
 * ------------------------------------------------------------------ */
static bool recipe_tee(struct iour_recipe_state *s,
		       bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int r;

	if (pipe(s->pipefd) < 0)
		return false;
	if (pipe(s->pipefd2) < 0)
		return false;

	{
		const char primer[64] = { 't', 'e', 'e' };
		ssize_t w __unused__ = write(s->pipefd[1], primer,
					     sizeof(primer));
	}

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_TEE;
	sqe.fd           = s->pipefd2[1];	/* out */
	sqe.splice_fd_in = s->pipefd[0];	/* in */
	sqe.len          = 64;
	sqe.splice_flags = 0;
	sqe.user_data    = 370;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: FILES_UPDATE on a pre-registered file table
 *
 * Register 4 placeholder slots, then submit FILES_UPDATE to swap one
 * slot in via the SQE.  The cleanup path UNREGISTERs the table.
 * ------------------------------------------------------------------ */
static bool recipe_files_update(struct iour_recipe_state *s,
				bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	int regfds[4] = { -1, -1, -1, -1 };
	int newfds[1];
	int r;

	s->open_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (s->open_fd < 0)
		return false;

	r = (int)syscall(__NR_io_uring_register, ctx->fd,
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
 * Recipe: LINK_TIMEOUT chained from a NOP
 *
 * LINK_TIMEOUT only makes sense as the second member of a linked pair;
 * it bounds the time the prior linked op may run.  NOP completes
 * instantly so the timeout itself fires the cancellation path harmlessly.
 * ------------------------------------------------------------------ */
static bool recipe_link_timeout(struct iour_recipe_state *s,
				bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqes[2];
	struct __kernel_timespec ts;
	int r;

	sqe_clear(&sqes[0]);
	sqes[0].opcode    = IORING_OP_NOP;
	sqes[0].flags     = IOSQE_IO_LINK;
	sqes[0].user_data = 390;

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000000;	/* 1 ms */

	sqe_clear(&sqes[1]);
	sqes[1].opcode        = IORING_OP_LINK_TIMEOUT;
	sqes[1].addr          = (__u64)(uintptr_t)&ts;
	sqes[1].len           = 1;
	sqes[1].timeout_flags = 0;
	sqes[1].user_data     = 391;

	if (!iour_submit_sqes(ctx, sqes, 2))
		return false;
	r = iour_enter(ctx, 2, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: TIMEOUT_REMOVE — submit a long timeout, then yank it
 * ------------------------------------------------------------------ */
static bool recipe_timeout_remove(struct iour_recipe_state *s,
				  bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	struct __kernel_timespec ts;
	int r;

	ts.tv_sec  = 60;
	ts.tv_nsec = 0;

	sqe_clear(&sqe);
	sqe.opcode        = IORING_OP_TIMEOUT;
	sqe.addr          = (__u64)(uintptr_t)&ts;
	sqe.len           = 1;
	sqe.timeout_flags = 0;
	sqe.user_data     = 400;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	if (iour_enter(ctx, 1, 0) < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode        = IORING_OP_TIMEOUT_REMOVE;
	sqe.addr          = 400;
	sqe.timeout_flags = 0;
	sqe.user_data     = 401;
	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 2);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: RENAMEAT on missing source (ENOENT but full prep+issue)
 *
 * SQE layout: sqe->fd=old_dfd, sqe->addr=oldpath, sqe->len=new_dfd
 * (an int packed as u32), sqe->addr2=newpath, sqe->rename_flags.
 * ------------------------------------------------------------------ */
static bool recipe_renameat(struct iour_recipe_state *s,
			    bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char oldp[] = "/tmp/trinity-iour-rn-src";
	static const char newp[] = "/tmp/trinity-iour-rn-dst";
	int r;

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_RENAMEAT;
	sqe.fd           = AT_FDCWD;
	sqe.addr         = (__u64)(uintptr_t)oldp;
	sqe.len          = (__u32)AT_FDCWD;
	sqe.addr2        = (__u64)(uintptr_t)newp;
	sqe.rename_flags = 0;
	sqe.user_data    = 410;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: UNLINKAT on a path that doesn't exist
 * ------------------------------------------------------------------ */
static bool recipe_unlinkat(struct iour_recipe_state *s,
			    bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[] = "/tmp/trinity-iour-unlink-target";
	int r;

	sqe_clear(&sqe);
	sqe.opcode       = IORING_OP_UNLINKAT;
	sqe.fd           = AT_FDCWD;
	sqe.addr         = (__u64)(uintptr_t)path;
	sqe.unlink_flags = 0;
	sqe.user_data    = 420;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: MKDIRAT — likely EEXIST or EACCES; prep + issue path runs
 * ------------------------------------------------------------------ */
static bool recipe_mkdirat(struct iour_recipe_state *s,
			   bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[] = "/tmp/trinity-iour-mkdir-target";
	int r;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_MKDIRAT;
	sqe.fd        = AT_FDCWD;
	sqe.addr      = (__u64)(uintptr_t)path;
	sqe.len       = 0700;
	sqe.user_data = 430;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: SYMLINKAT — likely EEXIST/EACCES; prep + issue path runs
 *
 * SQE layout: sqe->fd=newdirfd, sqe->addr=target (symlink contents),
 *             sqe->addr2=linkpath.
 * ------------------------------------------------------------------ */
static bool recipe_symlinkat(struct iour_recipe_state *s,
			     bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char target[] = "/dev/null";
	static const char linkp[]  = "/tmp/trinity-iour-symlink";
	int r;

	sqe_clear(&sqe);
	sqe.opcode    = IORING_OP_SYMLINKAT;
	sqe.fd        = AT_FDCWD;
	sqe.addr      = (__u64)(uintptr_t)target;
	sqe.addr2     = (__u64)(uintptr_t)linkp;
	sqe.user_data = 440;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: LINKAT — same SQE shape as RENAMEAT plus hardlink_flags
 * ------------------------------------------------------------------ */
static bool recipe_linkat(struct iour_recipe_state *s,
			  bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char oldp[] = "/dev/null";
	static const char newp[] = "/tmp/trinity-iour-hardlink";
	int r;

	sqe_clear(&sqe);
	sqe.opcode         = IORING_OP_LINKAT;
	sqe.fd             = AT_FDCWD;
	sqe.addr           = (__u64)(uintptr_t)oldp;
	sqe.len            = (__u32)AT_FDCWD;
	sqe.addr2          = (__u64)(uintptr_t)newp;
	sqe.hardlink_flags = 0;
	sqe.user_data      = 450;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Xattr SQE layout: sqe->addr=name ptr, sqe->addr3=value ptr,
 *                   sqe->len=size, sqe->xattr_flags=flags;
 *                   path-based variants additionally use sqe->addr2=path.
 * ------------------------------------------------------------------ */
static bool recipe_setxattr(struct iour_recipe_state *s,
			    bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[]  = "/tmp/trinity-iour-xattr-tgt";
	static const char name[]  = "user.trinity";
	static const char value[] = "v";
	int r;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_SETXATTR;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr2       = (__u64)(uintptr_t)path;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 460;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

static bool recipe_fsetxattr(struct iour_recipe_state *s,
			     bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char name[]  = "user.trinity";
	static const char value[] = "v";
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_FSETXATTR;
	sqe.fd          = s->memfd;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 470;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

static bool recipe_getxattr(struct iour_recipe_state *s,
			    bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char path[] = "/dev/null";
	static const char name[] = "user.trinity";
	char value[64];
	int r;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_GETXATTR;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr2       = (__u64)(uintptr_t)path;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 480;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

static bool recipe_fgetxattr(struct iour_recipe_state *s,
			     bool *unsupported __unused__)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	static const char name[] = "user.trinity";
	char value[64];
	int r;

	s->memfd = iour_make_memfd();
	if (s->memfd < 0)
		return false;

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_FGETXATTR;
	sqe.fd          = s->memfd;
	sqe.addr        = (__u64)(uintptr_t)name;
	sqe.addr3       = (__u64)(uintptr_t)value;
	sqe.len         = sizeof(value);
	sqe.xattr_flags = 0;
	sqe.user_data   = 490;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0)
		return false;
	iour_drain_cqes(ctx);
	return true;
}

/* ------------------------------------------------------------------ *
 * Recipe: WAITID on P_ALL with WNOHANG (likely ECHILD)
 *
 * SQE layout: sqe->len=which, sqe->fd=upid, sqe->file_index=options,
 *             sqe->addr2=infop ptr.
 * ------------------------------------------------------------------ */
static bool recipe_waitid(struct iour_recipe_state *s, bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqe;
	siginfo_t infop;
	int r;

	memset(&infop, 0, sizeof(infop));

	sqe_clear(&sqe);
	sqe.opcode      = IORING_OP_WAITID;
	sqe.len         = P_ALL;
	sqe.fd          = 0;
	sqe.file_index  = WNOHANG | WEXITED;
	sqe.addr2       = (__u64)(uintptr_t)&infop;
	sqe.user_data   = 500;

	if (!iour_submit_sqes(ctx, &sqe, 1))
		return false;
	r = iour_enter(ctx, 1, 1);
	if (r < 0) {
		if (errno == ENOSYS || errno == EINVAL) {
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

static bool recipe_eventfd_recursive(struct iour_recipe_state *s,
				     bool *unsupported)
{
	struct iour_ctx *ctx = s->ctx;
	struct io_uring_sqe sqes[8];
	eventfd_t bufs[8];
	uint64_t one = 1;
	struct io_uring_cqe *cqes;
	unsigned int nreads, reg_op, mask, head, tail, reaped, spins, i;
	bool ok = false;
	bool registered = false;
	int r;

	s->evfd = eventfd(0, EFD_NONBLOCK);
	if (s->evfd < 0)
		goto out;

	reg_op = ONE_IN(2) ? IORING_REGISTER_EVENTFD_ASYNC
			   : IORING_REGISTER_EVENTFD;

	r = (int)syscall(__NR_io_uring_register, ctx->fd, reg_op,
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

	nreads = 4 + ((unsigned int)rand() % 5);

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

	r = (int)syscall(__NR_io_uring_enter, ctx->fd, nreads, 0, 0, NULL, 0);
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
	cqes = (struct io_uring_cqe *)((char *)ctx->cq_ring + ctx->cq_off_cqes);
	mask = ring_u32(ctx->cq_ring, ctx->cq_off_mask);
	reaped = 0;
	for (spins = 0; spins < 32 && reaped < 32; spins++) {
		(void)syscall(__NR_io_uring_enter, ctx->fd, 0, 0,
			      IORING_ENTER_GETEVENTS, NULL, 0);

		head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
		while (head != tail && reaped < 32) {
			(void)cqes[head & mask];
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
		(void)syscall(__NR_io_uring_register, ctx->fd,
			      IORING_UNREGISTER_EVENTFD, NULL, 0);
	}
out:
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
#ifndef TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE
	{ "futex_wait_wake",        recipe_futex_wait_wake        },
#endif
	{ "epoll_wait",             recipe_epoll_wait             },
	{ "sendmsg",                recipe_sendmsg                },
	{ "recvmsg",                recipe_recvmsg                },
	{ "accept",                 recipe_accept                 },
	{ "connect",                recipe_connect                },
#ifndef TRINITY_COMPAT_BACKFILLED_BIND
	{ "bind",                   recipe_bind                   },
#endif
	{ "listen",                 recipe_listen                 },
	{ "fsync",                  recipe_fsync                  },
	{ "sync_file_range",        recipe_sync_file_range        },
	{ "readv",                  recipe_readv                  },
	{ "writev",                 recipe_writev                 },
	{ "fallocate",              recipe_fallocate              },
	{ "ftruncate",              recipe_ftruncate              },
	{ "fadvise",                recipe_fadvise                },
	{ "read_multishot",         recipe_read_multishot         },
	{ "openat2",                recipe_openat2                },
	{ "epoll_ctl",              recipe_epoll_ctl              },
	{ "splice",                 recipe_splice                 },
	{ "tee",                    recipe_tee                    },
	{ "files_update",           recipe_files_update           },
	{ "link_timeout",           recipe_link_timeout           },
	{ "timeout_remove",         recipe_timeout_remove         },
	{ "renameat",               recipe_renameat               },
	{ "unlinkat",               recipe_unlinkat               },
	{ "mkdirat",                recipe_mkdirat                },
	{ "symlinkat",              recipe_symlinkat              },
	{ "linkat",                 recipe_linkat                 },
	{ "setxattr",               recipe_setxattr               },
	{ "fsetxattr",              recipe_fsetxattr              },
	{ "getxattr",               recipe_getxattr               },
	{ "fgetxattr",              recipe_fgetxattr              },
	{ "waitid",                 recipe_waitid                 },
	{ "eventfd_recursive",      recipe_eventfd_recursive      },
	/*
	 * Deferred to follow-up: per-op submission requires setup the
	 * recipe harness doesn't track yet, so they're intentionally
	 * absent from the catalog rather than stubbed:
	 *   IORING_OP_FUTEX_WAITV       — needs a struct futex_waitv[] vector
	 *   IORING_OP_FIXED_FD_INSTALL  — needs a registered-file slot index
	 *                                 to be wired up at submission time
	 *   IORING_OP_NOP128            — needs IORING_SETUP_SQE128 ring
	 *   IORING_OP_URING_CMD128      — needs IORING_SETUP_SQE128 ring
	 */
};

_Static_assert(ARRAY_SIZE(catalog) <= MAX_IOURING_RECIPES,
	       "iouring recipe catalog outgrew MAX_IOURING_RECIPES; bump it");

bool iouring_recipes(struct childdata *child __unused__)
{
	struct iour_ctx ctx;
	struct iour_recipe_state state;
	const struct iour_recipe *r;
	/* volatile: read after sigsetjmp/siglongjmp window so the value
	 * must survive the longjmp register-clobber per ISO C 7.13.2.1. */
	volatile unsigned int idx;
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

	iour_recipe_state_init(&state, &ctx);

	{
		struct sigaction sa, old_segv, old_bus;
		bool aborted = false;

		/* Default empty range — non-pool-drawing recipes leave it
		 * empty so every si_addr falls outside and the handler
		 * defers to child_fault_handler.  The 3 pool-drawing
		 * recipes overwrite it from inside r->run() right after
		 * their get_map_with_prot() draw. */
		iouring_recipes_pool_race_addr_low  = 0;
		iouring_recipes_pool_race_addr_high = 0;

		memset(&sa, 0, sizeof(sa));
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO;
		sa.sa_sigaction = iouring_recipes_pool_race_handler;
		sigaction(SIGSEGV, &sa, &old_segv);
		sigaction(SIGBUS,  &sa, &old_bus);

		if (sigsetjmp(iouring_recipes_pool_race_jmp, 1) == 0) {
			ok = r->run(&state, &unsupported);
		} else {
			aborted = true;
			ok = false;
		}

		sigaction(SIGSEGV, &old_segv, NULL);
		sigaction(SIGBUS,  &old_bus,  NULL);

		iouring_recipes_pool_race_addr_low  = 0;
		iouring_recipes_pool_race_addr_high = 0;

		if (aborted) {
			/* siglongjmp skipped the recipe's own out: cleanup,
			 * but the per-iteration resources it allocated are
			 * recorded in &state and torn down by
			 * iour_recipe_state_cleanup() below.  The outer
			 * iour_teardown() then releases the ring mmaps + ring
			 * fd that iour_setup() populated above.  Don't latch
			 * iouring_recipe_disabled[idx] — faults are not
			 * ENOSYS. */
			__atomic_add_fetch(
				&shm->stats.pool_race_aborted[CHILD_OP_IOURING_RECIPES],
				1, __ATOMIC_RELAXED);
		}
	}

	iour_recipe_state_cleanup(&state);
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
