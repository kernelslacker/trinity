/*
 * iouring_flood - sustained io_uring submission pressure on freshly
 * created rings.
 *
 * Trinity already has iouring_recipes for structured, semantically
 * coherent submission sequences, but its dispatch is metered (one recipe
 * per invocation, narrow batches) so the per-ring submission fast path —
 * io_uring_enter, the SQE → work-item conversion, the inline completion
 * posting, and the CQ ring head/tail bookkeeping — only sees light
 * traffic.  iouring_flood closes that gap by repeatedly creating a small
 * ring, hammering it with bursts of NOP / READ / WRITE SQEs targeting
 * /dev/null, draining the resulting CQEs, and tearing the ring down.
 *
 * Per invocation: 1..MAX_CYCLES cycles.  Each cycle:
 *   - io_uring_setup with a small entry count and a randomised subset of
 *     IORING_SETUP_* flags
 *   - mmap the SQ ring, CQ ring (or alias if SINGLE_MMAP), and SQE array
 *   - submit a burst of MIN_BURST..MAX_BURST SQEs mixing NOP / READ /
 *     WRITE against /dev/null
 *   - io_uring_enter to submit and reap completions
 *   - munmap rings + close ring fd
 *
 * Self-bounding: the outer loop is hard-capped at MAX_CYCLES, the
 * per-cycle burst at MAX_BURST, and the alarm(1) the parent arms before
 * dispatch caps wall-clock time.  The kernel cannot block in
 * io_uring_enter because every chosen op completes inline — NOP returns
 * immediately, READ on /dev/null returns 0 (EOF), WRITE on /dev/null
 * discards.  No external state is touched (no fds outside /dev/null,
 * no shared mappings, no signals).
 *
 * On systems without CONFIG_IO_URING io_uring_setup returns ENOSYS; on
 * systems that disable user io_uring (kernel.io_uring_disabled sysctl)
 * it returns EPERM.  Either latches a per-process ns_unsupported flag
 * and subsequent invocations no-op — there's no point spinning on a
 * permission denial that won't change for the life of the process.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/io_uring.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup	425
#define __NR_io_uring_enter	426
#endif

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_SQES		0x10000000ULL
#endif

/* Hard cap on setup → submit → teardown cycles per invocation.  Sized so
 * the worst-case loop completes well inside the alarm(1) window even when
 * sibling churners are also hammering the kernel allocator. */
#define MAX_CYCLES	16

/* SQE entry count requested from io_uring_setup.  Small on purpose: the
 * point of this op is teardown / setup churn, not deep queues. */
#define RING_ENTRIES	32

/* Bounds on the per-cycle SQE burst submitted in one io_uring_enter.
 * MAX_BURST exceeds RING_ENTRIES on purpose — submit_burst clamps to
 * available ring space, so partial bursts naturally exercise the
 * "ring full" rejection path as well as the "fits cleanly" path. */
#define MIN_BURST	8
#define MAX_BURST	64

/* Latched per-child: io_uring_setup returned ENOSYS or EPERM once.  The
 * kernel was built without CONFIG_IO_URING, or io_uring is disabled by
 * sysctl — neither flips during this process's lifetime, so further
 * attempts are pure overhead. */
static bool ns_unsupported;

/* Page-sized buffer used for READ / WRITE SQEs.  Allocated lazily on
 * first use and reused across cycles within the same child — the kernel
 * writes zeros into it on READ from /dev/null and treats the WRITE
 * source as a discard buffer. */
static void *iobuf;
static size_t iobuf_sz;

/*
 * Per-cycle ring context.  All mmap'd regions live here so cleanup is a
 * single teardown call; ctx is fully zeroed on setup failure so callers
 * can short-circuit without inspecting individual fields.
 */
struct flood_ctx {
	int		fd;
	void		*sq_ring;
	void		*cq_ring;	/* aliases sq_ring when SINGLE_MMAP */
	void		*sqes;
	size_t		sq_ring_sz;
	size_t		cq_ring_sz;	/* 0 when SINGLE_MMAP */
	size_t		sqes_sz;
	bool		single_mmap;

	unsigned int	sq_entries;

	unsigned int	sq_off_head;
	unsigned int	sq_off_tail;
	unsigned int	sq_off_mask;
	unsigned int	sq_off_array;

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
 * Random subset of SETUP flags.  Kept conservative: only flags that do
 * not change the userspace contract (no NO_MMAP — we still need the
 * SQE / CQ regions in our address space; no SQPOLL / IOPOLL — those need
 * privilege or a pollable target).  An unsupported flag combo gets
 * rejected by the kernel with EINVAL, which flood_setup retries with no
 * flags so we still exercise the submission path on older kernels.
 */
static unsigned int pick_setup_flags(void)
{
	unsigned int flags = 0;

#ifdef IORING_SETUP_CLAMP
	if (RAND_BOOL())
		flags |= IORING_SETUP_CLAMP;
#endif
#ifdef IORING_SETUP_SUBMIT_ALL
	if (RAND_BOOL())
		flags |= IORING_SETUP_SUBMIT_ALL;
#endif
#ifdef IORING_SETUP_COOP_TASKRUN
	if (RAND_BOOL())
		flags |= IORING_SETUP_COOP_TASKRUN;
#endif
#ifdef IORING_SETUP_TASKRUN_FLAG
	if (RAND_BOOL())
		flags |= IORING_SETUP_TASKRUN_FLAG;
#endif
	return flags;
}

static int do_setup(struct io_uring_params *p, unsigned int entries)
{
	return (int)syscall(__NR_io_uring_setup, entries, p);
}

static bool flood_setup(struct flood_ctx *ctx)
{
	struct io_uring_params p;
	size_t sq_sz, cq_sz, sqes_sz;
	void *sq_ring, *cq_ring, *sqes;
	int fd;

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;

	memset(&p, 0, sizeof(p));
	p.flags = pick_setup_flags();

	fd = do_setup(&p, RING_ENTRIES);
	if (fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP)) {
		/* Flag combo not accepted on this kernel — retry with no
		 * flags so the submission path still gets exercised. */
		memset(&p, 0, sizeof(p));
		fd = do_setup(&p, RING_ENTRIES);
	}
	if (fd < 0)
		return false;

	sq_sz   = (size_t)p.sq_off.array + (size_t)p.sq_entries * sizeof(unsigned int);
	cq_sz   = (size_t)p.cq_off.cqes  + (size_t)p.cq_entries * sizeof(struct io_uring_cqe);
	sqes_sz = (size_t)p.sq_entries   * sizeof(struct io_uring_sqe);

	sq_ring = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (sq_ring == MAP_FAILED) {
		close(fd);
		return false;
	}

	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		cq_ring = sq_ring;
		ctx->single_mmap = true;
	} else {
		cq_ring = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_POPULATE,
			       fd, IORING_OFF_CQ_RING);
		if (cq_ring == MAP_FAILED) {
			munmap(sq_ring, sq_sz);
			close(fd);
			return false;
		}
	}

	sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (sqes == MAP_FAILED) {
		if (!ctx->single_mmap)
			munmap(cq_ring, cq_sz);
		munmap(sq_ring, sq_sz);
		close(fd);
		return false;
	}

	ctx->fd          = fd;
	ctx->sq_ring     = sq_ring;
	ctx->sq_ring_sz  = sq_sz;
	ctx->cq_ring     = cq_ring;
	ctx->cq_ring_sz  = ctx->single_mmap ? 0 : cq_sz;
	ctx->sqes        = sqes;
	ctx->sqes_sz     = sqes_sz;
	ctx->sq_entries  = p.sq_entries;

	ctx->sq_off_head  = p.sq_off.head;
	ctx->sq_off_tail  = p.sq_off.tail;
	ctx->sq_off_mask  = p.sq_off.ring_mask;
	ctx->sq_off_array = p.sq_off.array;

	ctx->cq_off_head  = p.cq_off.head;
	ctx->cq_off_tail  = p.cq_off.tail;
	ctx->cq_off_mask  = p.cq_off.ring_mask;
	ctx->cq_off_cqes  = p.cq_off.cqes;

	return true;
}

static void flood_teardown(struct flood_ctx *ctx)
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
 * Fill an SQE with one of: NOP, READ on dev_null_rd, WRITE on dev_null_wr.
 * The buffer + len are clamped to half iobuf_sz so a READ never overruns
 * the page when the kernel returns short.
 */
static void fill_sqe(struct io_uring_sqe *s,
		     int dev_null_rd, int dev_null_wr,
		     unsigned int seq)
{
	memset(s, 0, sizeof(*s));
	s->user_data = seq;

	switch (rand() % 3) {
	case 0:
		s->opcode = IORING_OP_NOP;
		break;
	case 1:
		s->opcode = IORING_OP_READ;
		s->fd     = dev_null_rd;
		s->addr   = (__u64)(uintptr_t)iobuf;
		s->len    = (unsigned int)(iobuf_sz / 2);
		s->off    = 0;
		break;
	default:
		s->opcode = IORING_OP_WRITE;
		s->fd     = dev_null_wr;
		s->addr   = (__u64)(uintptr_t)iobuf;
		s->len    = (unsigned int)(iobuf_sz / 2);
		s->off    = 0;
		break;
	}
}

/*
 * Place the prepared SQEs into the submission ring and publish the new
 * tail.  Returns the number actually queued (clamped to available ring
 * space), or 0 if the ring was already full.
 */
static unsigned int submit_burst(struct flood_ctx *ctx,
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
		n = avail;
	if (n == 0)
		return 0;

	sq_array = (unsigned int *)((char *)ctx->sq_ring + ctx->sq_off_array);

	for (i = 0; i < n; i++) {
		unsigned int slot = (tail + i) & mask;

		sqes[slot] = sqe[i];
		sq_array[slot] = slot;
	}

	__sync_synchronize();
	ring_store_u32(ctx->sq_ring, ctx->sq_off_tail, tail + n);
	return n;
}

/* Drain all available CQEs and return how many were reaped. */
static unsigned int drain_cqes(struct flood_ctx *ctx)
{
	unsigned int mask = ring_u32(ctx->cq_ring, ctx->cq_off_mask);
	unsigned int head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	unsigned int tail;
	unsigned int reaped = 0;
	struct io_uring_cqe *cqes;

	cqes = (struct io_uring_cqe *)((char *)ctx->cq_ring + ctx->cq_off_cqes);
	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		(void)cqes[head & mask];
		head++;
		reaped++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);
	return reaped;
}

bool iouring_flood(struct childdata *child)
{
	struct io_uring_sqe burst[MAX_BURST];
	unsigned int cycles;
	unsigned int i;
	int dev_null_rd = -1;
	int dev_null_wr = -1;

	(void)child;

	__atomic_add_fetch(&shm->stats.iouring_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	/* Lazy alloc of the shared READ / WRITE buffer.  Each child is a
	 * separate process so this static lives in the child's private
	 * address space; the mapping survives across invocations within
	 * the same child. */
	if (iobuf == NULL) {
		iobuf_sz = page_size;
		iobuf = mmap(NULL, iobuf_sz, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (iobuf == MAP_FAILED) {
			iobuf = NULL;
			iobuf_sz = 0;
			__atomic_add_fetch(&shm->stats.iouring_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		memset(iobuf, 'F', iobuf_sz);
	}

	dev_null_rd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	dev_null_wr = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (dev_null_rd < 0 || dev_null_wr < 0) {
		if (dev_null_rd >= 0) close(dev_null_rd);
		if (dev_null_wr >= 0) close(dev_null_wr);
		__atomic_add_fetch(&shm->stats.iouring_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	cycles = 1 + ((unsigned int)rand() % MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct flood_ctx ctx;
		unsigned int n_pick;
		unsigned int n_subs;
		unsigned int j;
		int r;

		if (!flood_setup(&ctx)) {
			/* ENOSYS: kernel built without CONFIG_IO_URING.
			 * EPERM:  io_uring disabled by sysctl.  Neither
			 * changes for the life of this process — latch
			 * and bail so subsequent invocations no-op. */
			if (errno == ENOSYS || errno == EPERM) {
				ns_unsupported = true;
				break;
			}
			__atomic_add_fetch(&shm->stats.iouring_failed,
					   1, __ATOMIC_RELAXED);
			continue;
		}

		n_pick = MIN_BURST + ((unsigned int)rand() %
				      (MAX_BURST - MIN_BURST + 1));

		for (j = 0; j < n_pick; j++)
			fill_sqe(&burst[j], dev_null_rd, dev_null_wr, j + 1);

		n_subs = submit_burst(&ctx, burst, n_pick);
		if (n_subs == 0) {
			__atomic_add_fetch(&shm->stats.iouring_failed,
					   1, __ATOMIC_RELAXED);
			flood_teardown(&ctx);
			continue;
		}

		r = (int)syscall(__NR_io_uring_enter, ctx.fd, n_subs,
				 n_subs, IORING_ENTER_GETEVENTS, NULL, 0);
		if (r < 0) {
			__atomic_add_fetch(&shm->stats.iouring_failed,
					   1, __ATOMIC_RELAXED);
		} else {
			unsigned int reaped;

			__atomic_add_fetch(&shm->stats.iouring_submits,
					   (unsigned long)n_subs,
					   __ATOMIC_RELAXED);
			reaped = drain_cqes(&ctx);
			__atomic_add_fetch(&shm->stats.iouring_reaped,
					   (unsigned long)reaped,
					   __ATOMIC_RELAXED);
		}

		flood_teardown(&ctx);
	}

	close(dev_null_rd);
	close(dev_null_wr);

	return true;
}
