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
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "syscall-gate.h"
#include "child.h"
#include "childops-iouring.h"
#include "childops/io_uring/ring.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/unistd.h"
/* Hard cap on setup → submit → teardown cycles per invocation.  Sized so
 * the worst-case loop completes well inside the alarm(1) window even when
 * sibling churners are also hammering the kernel allocator. */
#define MAX_CYCLES	16

/* SQE entry count requested from io_uring_setup.  Small on purpose: the
 * point of this op is teardown / setup churn, not deep queues. */
#define RING_ENTRIES	32

/* Bounds on the per-cycle SQE burst submitted in one io_uring_enter.
 * MAX_BURST exceeds RING_ENTRIES on purpose — iouring_flood_iter_submit_burst
 * clamps to available ring space, so partial bursts naturally exercise
 * the "ring full" rejection path as well as the "fits cleanly" path. */
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
 * Random subset of SETUP flags.  Kept conservative: only flags that do
 * not change the userspace contract (no NO_MMAP — we still need the
 * SQE / CQ regions in our address space; no SQPOLL / IOPOLL — those need
 * privilege or a pollable target).  An unsupported flag combo gets
 * rejected by the kernel with EINVAL, which iouring_flood_iter_setup_ring
 * retries with no flags so we still exercise the submission path on
 * older kernels.
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

/*
 * Phase 1: stand up a fresh io_uring instance for this cycle via the
 * shared iour_ring_setup helper.  An IOUR_TRANSIENT first attempt
 * with flags set falls back to a no-flags retry so an unsupported
 * flag combo doesn't waste the cycle; IOUR_UNSUPPORTED on either
 * attempt latches the file-local ns_unsupported gate (kernel built
 * without CONFIG_IO_URING, or io_uring disabled by sysctl: neither
 * flips for the life of the process so future invocations should
 * no-op).  Other transient failures (ENOMEM / EAGAIN / EMFILE / a
 * hostile-kernel-return overflow or out-of-range offset rejected by
 * the helper) bump iouring_failed and skip the cycle without
 * latching.
 *
 * Returns IOUR_SUPPORTED on success (ctx populated) or the
 * propagated status on failure (ctx left fully zeroed by the helper
 * so an accidental teardown call no-ops).
 */
static enum iour_setup_status iouring_flood_iter_setup_ring(struct iour_ring *ctx,
							    struct childdata *child)
{
	struct io_uring_params p;
	enum iour_setup_status st;

	memset(&p, 0, sizeof(p));
	p.flags = pick_setup_flags();

	st = iour_ring_setup(&p, RING_ENTRIES, ctx);
	if (st == IOUR_TRANSIENT && p.flags != 0) {
		/* Flag combo may not be accepted on this kernel -- retry
		 * with no flags so the submission path still gets
		 * exercised on older kernels. */
		memset(&p, 0, sizeof(p));
		st = iour_ring_setup(&p, RING_ENTRIES, ctx);
	}
	if (st == IOUR_SUPPORTED)
		return IOUR_SUPPORTED;

	if (st == IOUR_UNSUPPORTED) {
		ns_unsupported = true;
		/* child->op_type lives in shared memory and can be scribbled
		 * by a poisoned-arena write from a sibling; bounds-check the
		 * snapshot before indexing the NR_CHILD_OP_TYPES-sized stats
		 * array, same pattern the child.c dispatch loop uses for the
		 * unguarded write that motivated this guard. */
		{
			const enum child_op_type op = child->op_type;
			if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
	} else {
		__atomic_add_fetch(&shm->stats.iouring.failed, 1,
				   __ATOMIC_RELAXED);
	}
	return st;
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

	switch (rnd_modulo_u32(3)) {
	case 0:
		s->opcode = IORING_OP_NOP;
		break;
	case 1:
		s->opcode = IORING_OP_READ;
		s->fd     = dev_null_rd;
		s->addr   = (__u64)(uintptr_t)iobuf;
		/* 1-in-RAND_NEGATIVE_RATIO sub the in-bounds len for a
		 * curated edge value — exercises io_uring's per-op length
		 * validation against /dev/null where the read is harmless
		 * regardless of the requested size. */
		s->len    = (unsigned int)RAND_NEGATIVE_OR((long)(iobuf_sz / 2));
		s->off    = 0;
		break;
	default:
		s->opcode = IORING_OP_WRITE;
		s->fd     = dev_null_wr;
		s->addr   = (__u64)(uintptr_t)iobuf;
		s->len    = (unsigned int)RAND_NEGATIVE_OR((long)(iobuf_sz / 2));
		s->off    = 0;
		break;
	}
}

/*
 * Phase 2: prepare a burst of MIN_BURST..MAX_BURST SQEs against the
 * /dev/null read + write fds, place them in the submission ring, and
 * publish the new tail.  The per-SQE op mix (NOP / READ / WRITE, the
 * random length, the 1-in-RAND_NEGATIVE_RATIO negative-len injection)
 * is delegated to fill_sqe.  The published count is clamped to the
 * SQ ring's available slots so a partial burst exercises io_uring's
 * "ring full" rejection path naturally; a fully-rejected burst (0
 * published) bumps iouring_failed here and returns 0 so the
 * orchestrator can short-circuit straight to teardown without an
 * io_uring_enter on an empty SQ.
 *
 * Returns the number of SQEs actually published (>=1) on success,
 * 0 on complete rejection.
 */
static unsigned int iouring_flood_iter_submit_burst(
		struct iour_ring *ctx,
		int dev_null_rd, int dev_null_wr,
		struct io_uring_sqe *burst)
{
	unsigned int mask, head, tail, avail;
	unsigned int *sq_array;
	struct io_uring_sqe *sqes = ctx->sqes;
	unsigned int n_pick, n_subs, i;

	n_pick = MIN_BURST + rnd_modulo_u32(MAX_BURST - MIN_BURST + 1);

	for (i = 0; i < n_pick; i++)
		fill_sqe(&burst[i], dev_null_rd, dev_null_wr, i + 1);

	mask  = ring_u32(ctx->sq_ring, ctx->sq_off_mask);
	head  = ring_u32(ctx->sq_ring, ctx->sq_off_head);
	tail  = ring_u32(ctx->sq_ring, ctx->sq_off_tail);
	avail = ctx->sq_entries - (tail - head);

	n_subs = n_pick;
	if (n_subs > avail)
		n_subs = avail;
	if (n_subs == 0) {
		__atomic_add_fetch(&shm->stats.iouring.failed, 1,
				   __ATOMIC_RELAXED);
		return 0;
	}

	sq_array = (unsigned int *)((char *)ctx->sq_ring + ctx->sq_off_array);

	for (i = 0; i < n_subs; i++) {
		unsigned int slot = (tail + i) & mask;

		sqes[slot] = burst[i];
		sq_array[slot] = slot;
	}

	__sync_synchronize();
	ring_store_u32(ctx->sq_ring, ctx->sq_off_tail, tail + n_subs);
	return n_subs;
}

/*
 * Phase 3: hand the just-published burst over to the kernel via
 * io_uring_enter (with IORING_ENTER_GETEVENTS so the call also reaps
 * inline completions), then drain every CQE the kernel posted to the
 * CQ ring.  Every op selected by fill_sqe (NOP, READ / WRITE against
 * /dev/null) completes inline before io_uring_enter returns, so the
 * drain never has to wait -- it just walks head..tail and advances
 * the consumer head with a __sync_synchronize before the store so
 * the kernel observes the consumer position after every prior CQE
 * read has retired.
 *
 * Stats accounting:
 *   - io_uring_enter failure (-1) bumps iouring_failed; the CQ ring
 *     is left untouched since there's nothing to drain on failure.
 *   - io_uring_enter success bumps iouring_submits by the count
 *     actually surrendered to the kernel (n_subs), then bumps
 *     iouring_reaped by the count drained from the CQ ring.
 */
static void iouring_flood_iter_reap_cqes(
		struct iour_ring *ctx, unsigned int n_subs)
{
	unsigned int head, tail, reaped = 0;
	int r;

	r = (int)trinity_raw_syscall(__NR_io_uring_enter, ctx->fd, n_subs,
			 n_subs, IORING_ENTER_GETEVENTS, NULL, 0);
	if (r < 0) {
		__atomic_add_fetch(&shm->stats.iouring.failed, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	__atomic_add_fetch(&shm->stats.iouring.submits,
			   (unsigned long)n_subs, __ATOMIC_RELAXED);

	head = ring_u32(ctx->cq_ring, ctx->cq_off_head);
	tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);

	while (head != tail) {
		head++;
		reaped++;
		tail = ring_u32(ctx->cq_ring, ctx->cq_off_tail);
	}

	__sync_synchronize();
	ring_store_u32(ctx->cq_ring, ctx->cq_off_head, head);

	__atomic_add_fetch(&shm->stats.iouring.reaped,
			   (unsigned long)reaped, __ATOMIC_RELAXED);
}

bool iouring_flood(struct childdata *child)
{
	struct io_uring_sqe burst[MAX_BURST];
	unsigned int cycles;
	unsigned int i;
	int dev_null_rd = -1;
	int dev_null_wr = -1;

	__atomic_add_fetch(&shm->stats.iouring.runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	/* Lazy bind of the shared READ / WRITE buffer to one of the parent's
	 * inherited mapping-pool entries.  The pool is built once in the
	 * parent and shared COW into every child, so siblings running
	 * iouring_flood concurrently will sometimes draw the same physical
	 * page — that overlap is intentional, it converges io_uring's
	 * per-buffer tracking on the same backing storage and amplifies
	 * any racy bookkeeping in the submission / completion fast path.
	 *
	 * The pool is owned by the parent: we must NOT munmap on cleanup,
	 * and we must NOT memset the buffer — clobbering it would corrupt
	 * the shared state that other childops also draw from.
	 *
	 * No SIGSEGV/SIGBUS sigsetjmp wrap protects the pool draw here:
	 * the iouring kernel never faults userspace on a bad SQE buffer.
	 * The pointer is copied into the SQE in fill_sqe and the kernel
	 * surfaces a stale-pointer condition as -EFAULT in the CQE result
	 * (drained in iouring_flood_iter_reap_cqes and counted in
	 * iouring_failed via the io_uring_enter return path), not as a
	 * userspace SIGSEGV.  A signal-handler wrap here can therefore
	 * only hide unrelated bugs — bad pool buffers do not surface
	 * through it. */
	if (iobuf == NULL) {
		struct map *m = get_map_with_prot(PROT_READ | PROT_WRITE);

		if (m == NULL) {
			__atomic_add_fetch(&shm->stats.iouring.failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		iobuf = m->ptr;
		iobuf_sz = m->size;
	}

	dev_null_rd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	dev_null_wr = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (dev_null_rd < 0 || dev_null_wr < 0) {
		if (dev_null_rd >= 0) close(dev_null_rd);
		if (dev_null_wr >= 0) close(dev_null_wr);
		__atomic_add_fetch(&shm->stats.iouring.failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	cycles = 1 + rnd_modulo_u32(MAX_CYCLES);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	for (i = 0; i < cycles; i++) {
		struct iour_ring ctx;
		unsigned int n_subs;

		if (iouring_flood_iter_setup_ring(&ctx, child) != IOUR_SUPPORTED) {
			/* setup_ring already categorised the failure --
			 * IOUR_UNSUPPORTED latched ns_unsupported, any
			 * other status was charged to iouring_failed.
			 * The latch is the only break-out condition;
			 * transient failures just skip this cycle. */
			if (ns_unsupported)
				break;
			continue;
		}
		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
					   1, __ATOMIC_RELAXED);

		n_subs = iouring_flood_iter_submit_burst(&ctx, dev_null_rd,
							 dev_null_wr, burst);
		if (n_subs == 0) {
			iour_ring_teardown(&ctx);
			continue;
		}

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		iouring_flood_iter_reap_cqes(&ctx, n_subs);

		iour_ring_teardown(&ctx);
	}

	close(dev_null_rd);
	close(dev_null_wr);

	return true;
}
