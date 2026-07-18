/*
 * madvise_cycler - sweep recent madvise() advice modes across a single
 * pool-drawn region per invocation.
 *
 * Trinity's random_syscall path issues madvise(2) with arbitrary advice
 * values against arbitrary addr/len pairs, so most calls fault out at
 * range validation (-EINVAL / -ENOMEM) before reaching the per-advice
 * handler.  Several madvise modes — MADV_FREE, MADV_COLD, MADV_PAGEOUT,
 * MADV_POPULATE_READ/WRITE, MADV_COLLAPSE — are recent kernel additions
 * (5.4 / 5.10 / 5.14 / 6.1 timeframe) whose lazyfree-LRU walks, deferred
 * reclaim, prefault loops and THP collapse machinery only see sustained
 * fuzz coverage when called on a *valid* writable region.  madvise_cycler
 * closes that gap by:
 *
 *   - Drawing one writable mapping from the global pool via
 *     get_map_with_prot(PROT_READ|PROT_WRITE).  Most of the curated
 *     advice modes fault, mark or rewrite ptes, so the region must be
 *     writable; PROT_READ-only or PROT_NONE entries would either return
 *     -EACCES (POPULATE_WRITE) or never touch the interesting paths.
 *   - Cycling through a curated advice list, applying ONE madvise per
 *     loop iteration to a randomly-chosen page-aligned sub-range whose
 *     length is capped at region/2.  The sub-range cap leaves headroom
 *     for variation so successive iterations hit different parts of the
 *     VMA, and forces the kernel to walk partial-VMA paths (madvise's
 *     vma_split branch) rather than always operating on the whole VMA.
 *   - Optionally touching a few pages after each advice, RAND_BOOL()
 *     selecting read vs write, to drive the fault-in / refault behaviour
 *     against pages that were just FREE'd / PAGEOUT'd / COLD'd.
 *
 * The advice list is curated, not random across the whole MADV_*
 * namespace: the random_syscall path already covers the bizarre/invalid
 * combinations.  The point of this op is sustained, valid coverage of
 * the recently-added modes that random_syscall barely reaches.
 *
 * MADV_NORMAL is included as a "reset" between aggressive modes so the
 * VMA flag state churns rather than monotonically accumulating advice.
 *
 * MADV_COLLAPSE may return -EINVAL if the range is not THP-eligible
 * (size, alignment, or transparent_hugepage policy).  That's expected
 * and counted as a regular failure; the call itself still exercised
 * khugepaged_collapse_single_pmd's eligibility check, which is the
 * fuzz-relevant entry point.
 *
 * No private allocation: the pool entry is owned by the parent and
 * remains alive after return — this op never munmap()s it.
 *
 * Self-bounding:
 *   - MAX_ITERATIONS caps inner-loop iterations.
 *   - BUDGET_NS (200 ms) sits in the same band as the other mm/region
 *     thrash ops (memory_pressure, mlock_pressure, pidfd_storm).
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged madvise path here still trips the SIGALRM stall detector.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <string.h>
#include <time.h>

#include "arch.h"
#include "pids.h"
#include "child.h"
#include "childops-util.h"
#include "jitter.h"
#include "maps.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "vma-pressure.h"

#include "kernel/mman.h"
/* Recent madvise advice modes - libc headers on older build hosts may
 * not define these even though the running kernel supports them.
 * Mirror the values from include/kernel/mman.h so we can build cleanly
 * without dragging unnecessary headers into this TU. */
#ifndef MADV_FREE
#define MADV_FREE	8
#endif
#ifndef MADV_COLD
#define MADV_COLD	20
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT	21
#endif
#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ	22
#endif
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE	23
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE	25
#endif

/* Wall-clock ceiling for the inner cycle loop.  Same band as
 * pidfd_storm / pipe_thrash / flock_thrash so dump_stats keeps ticking
 * and SIGALRM stall detection still has headroom. */
#define BUDGET_NS	200000000L	/* 200 ms */

/* Default cap on inner cycle iterations.  Each iteration is one madvise()
 * plus an optional small touch loop; both are cheap, so 64 gives plenty
 * of cache-hot pressure without risking the SIGALRM stall detector.
 * This is the BUDGETED() base — adapt_budget() can scale it from 0.25x
 * to 4x (16 to 256 iters) based on the recent kcov edge-rate signal.
 * The wall-clock BUDGET_NS still applies as the absolute backstop. */
#define MAX_ITERATIONS	64

/* Curated advice set.  Recent modes that random_syscall barely covers
 * with valid args, plus MADV_DONTNEED (the canonical anonymous-zap
 * baseline, useful as a control between the lazier MADV_FREE and the
 * reclaim-driven MADV_PAGEOUT) and MADV_NORMAL as a reset. */
static const unsigned long advice_cycle[] = {
	MADV_FREE,
	MADV_COLD,
	MADV_PAGEOUT,
	MADV_POPULATE_READ,
	MADV_POPULATE_WRITE,
	MADV_DONTNEED,
	MADV_COLLAPSE,
	MADV_NORMAL,
};

/*
 * Pick a page-aligned sub-range whose length is capped at region/2.
 * The cap leaves room for variation across iterations so successive
 * advices hit different parts of the VMA and force partial-VMA paths
 * (madvise_walk_vmas / vma_split) rather than always whole-VMA.
 *
 * Returns the offset from base; *lenp receives the byte length.
 * Caller has already ensured nr_pages >= 2 (single-page mappings are
 * rejected up front in madvise_cycler before this is called).
 */
static unsigned long pick_subrange(unsigned long nr_pages, unsigned long *lenp)
{
	unsigned long max_pages, len_pages, start_page, max_start;

	/* Cap length at region/2 (round down).  Always at least 1 page. */
	max_pages = nr_pages / 2;
	if (max_pages == 0)
		max_pages = 1;

	len_pages = 1 + rnd_modulo_u32(max_pages);

	/* Choose start so [start_page, start_page + len_pages) fits. */
	max_start = nr_pages - len_pages;
	start_page = (max_start == 0) ? 0 : rnd_modulo_u32(max_start + 1);

	*lenp = len_pages * page_size;
	return start_page * page_size;
}

/*
 * Touch a handful of pages within the just-advised sub-range to drive
 * fault-in / refault behaviour against pages the kernel may have just
 * marked lazyfree, deactivated, or reclaimed.  RAND_BOOL() picks
 * read vs write — write fires the dirty-pte path; read alone is
 * enough to fault MADV_FREE / MADV_PAGEOUT pages back in.
 *
 * Bounded to a small number of strided touches so the touch cost is
 * trivially small relative to the budget.
 */
static void touch_subrange(volatile unsigned char *base, unsigned long len)
{
	unsigned long stride, off;
	bool do_write;

	/* Stride larger than page_size to avoid coalescing into a single
	 * readahead window; we want each touch to drive an independent
	 * fault path. */
	stride = 3 * page_size;
	do_write = RAND_BOOL();

	for (off = 0; off < len; off += stride) {
		if (do_write)
			base[off] = (unsigned char) (off & 0xff);
		else
			(void) base[off];
	}
}

/* Pool-race fault guard.  See childops/mm/memory-pressure.c for the full
 * rationale.  The wrap below catches a sibling-driven UAF on the
 * pool-drawn region between draw and the touch_subrange() write/read
 * inside the iter loop, but only when si_addr is inside the drawn
 * pool mapping range.  Faults outside the range — ASAN redzone hits,
 * setup-path bugs, genuine SIGBUS on an unrelated mmap — restore
 * SIG_DFL and re-raise so child_fault_handler diagnoses + exits and
 * the per-pid bug log path is preserved.  Volatile, ordering, and
 * re-raise rationale match the equivalent statics in
 * childops/mm/memory-pressure.c. */
static sigjmp_buf madvise_cycler_pool_race_jmp;
static volatile uintptr_t madvise_cycler_pool_race_addr_low;
static volatile uintptr_t madvise_cycler_pool_race_addr_high;

static __attribute__((no_sanitize("address")))
void madvise_cycler_pool_race_handler(int sig, siginfo_t *info,
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
	if (fault_addr < madvise_cycler_pool_race_addr_low ||
	    fault_addr >= madvise_cycler_pool_race_addr_high) {
		/* Real kernel fault but si_addr is outside the drawn
		 * pool range — not the race we're guarding against.
		 * Restore default and re-raise so child_fault_handler
		 * diagnoses + exits and the bug log path is preserved. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(madvise_cycler_pool_race_jmp, 1);
}

/*
 * Per-invocation state shared across the madvise_cycler_iter_* helpers.
 * Lives on the orchestrator's stack and is fresh per call.  region /
 * region_len / nr_pages are filled by pick_region; advice_idx and start
 * are filled by setup_budget and then read + advanced by run_cycle.
 * iter_cap stays out of this struct -- see the volatile comment on the
 * orchestrator's iter_cap declaration.
 */
struct madvise_cycler_iter_ctx {
	unsigned char	*region;
	unsigned long	 region_len;
	unsigned long	 nr_pages;
	unsigned int	 advice_idx;
	struct timespec	 start;
};

/*
 * Phase 1: draw a writable region from the parent's inherited mapping
 * pool.  Most of the curated advice modes (PAGEOUT, FREE, POPULATE_WRITE,
 * COLLAPSE) need to walk and modify ptes on a writable VMA; PROT_READ-
 * only / PROT_NONE entries would either return early or fail -EACCES
 * before hitting the interesting paths.  The pool entry is owned by
 * the parent and remains alive after return -- this op never munmap()s
 * it; tearing down a pool entry would unmap pages every other sibling
 * drawing the same map is still treating as live.
 *
 * Returns 0 on success (ctx->region / region_len / nr_pages populated),
 * -1 if the pool yielded no writable mapping (caller bails false), or
 * 1 if the region is single-page so pick_subrange's region/2 cap would
 * collapse to whole-VMA every iteration (caller bails true: no useful
 * work, but not a dispatch-level failure).
 */
static int madvise_cycler_iter_pick_region(struct madvise_cycler_iter_ctx *ctx)
{
	struct map *m;

	m = get_map_with_prot(PROT_READ | PROT_WRITE);
	if (m == NULL)
		return -1;

	ctx->region = (unsigned char *) m->ptr;
	ctx->region_len = m->size;
	ctx->nr_pages = ctx->region_len / page_size;
	if (ctx->nr_pages < 2)
		return 1;
	return 0;
}

/*
 * Phase 2: stamp the wall-clock start (read by budget_elapsed_ns inside
 * the cycle loop) and pick the starting offset into the curated advice
 * list.  Uniform-random start ensures every advice value gets the same
 * chance to land first while the wall-clock budget is still fresh; this
 * also keeps concurrent madvise_cycler invocations from all hammering
 * MADV_FREE first.  Nothing here touches the pool mapping, so a fault
 * during setup is not a pool race and the default handler still wins.
 */
static void madvise_cycler_iter_setup_budget(struct madvise_cycler_iter_ctx *ctx)
{
	clock_gettime(CLOCK_MONOTONIC, &ctx->start);
	ctx->advice_idx = rnd_modulo_u32(ARRAY_SIZE(advice_cycle));
}

/*
 * Phase 3: publish the drawn region's [low, high) bounds for the
 * pool-race fault handler to test si_addr against, then install the
 * SIGSEGV / SIGBUS handlers and stash the prior dispositions for
 * disarm to restore.  Publishing the bounds before sigaction is
 * deliberate: the handler reads the bounds, so the bounds must be
 * visible the instant either signal is steerable to our handler.
 * Caller-supplied out-params receive the prior dispositions; both must
 * survive the sigsetjmp wrap so disarm can put them back.
 */
static void madvise_cycler_iter_arm_guard(const struct madvise_cycler_iter_ctx *ctx,
					  struct sigaction *old_segv,
					  struct sigaction *old_bus)
{
	struct sigaction sa;

	madvise_cycler_pool_race_addr_low  = (uintptr_t)ctx->region;
	madvise_cycler_pool_race_addr_high = (uintptr_t)ctx->region + ctx->region_len;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = madvise_cycler_pool_race_handler;
	sigaction(SIGSEGV, &sa, old_segv);
	sigaction(SIGBUS,  &sa, old_bus);
}

/*
 * Phase 4: the BUDGETED inner loop -- run up to iter_cap iterations,
 * each one applying one curated madvise to a random page-aligned sub-
 * range with an occasional length perturbation, optionally faulting
 * a few pages back in, and bailing early on wall-clock budget.  Lives
 * INSIDE the sigsetjmp wrap: a sibling-driven UAF on the pool region
 * during madvise / touch_subrange siglongjmps the outer body, skipping
 * the remaining iterations of this function -- there are no per-
 * iteration allocations to leak, by design.  iter_cap is passed by
 * value (the orchestrator owns the volatile-qualified storage that
 * tames -Wclobbered against BUDGETED's _b temp); ctx->advice_idx and
 * ctx->start are read/advanced through the pointer.
 */
static void madvise_cycler_iter_run_cycle(struct madvise_cycler_iter_ctx *ctx,
					  unsigned int iter_cap)
{
	unsigned int iter;

	for (iter = 0; iter < iter_cap; iter++) {
		unsigned long offset, len;
		int advice, mrc;

		/* Global VMA-pressure backoff.  Most curated advice modes
		 * here (FREE / COLD / PAGEOUT / POPULATE_* / COLLAPSE) take
		 * the partial-VMA path inside madvise_walk_vmas, which can
		 * split.  Bail the remainder of the cycle on a latch. */
		if (vma_pressure_is_high())
			break;

		offset = pick_subrange(ctx->nr_pages, &len);
		advice = (int)advice_cycle[ctx->advice_idx];
		ctx->advice_idx = (ctx->advice_idx + 1) %
			(unsigned int)ARRAY_SIZE(advice_cycle);

		/* 1-in-RAND_NEGATIVE_RATIO sub the page-aligned
		 * valid len for a curated edge value —
		 * exercises the kernel's range validation
		 * (PAGE_ALIGN overflow, end < start, len near
		 * SIZE_MAX) which the partial-VMA path above
		 * never reaches. */
		mrc = madvise(ctx->region + offset,
			      (size_t)RAND_NEGATIVE_OR(len),
			      advice);
		__atomic_add_fetch(
			&shm->stats.madvise_cycler.calls,
			1, __ATOMIC_RELAXED);
		if (mrc < 0) {
			__atomic_add_fetch(
				&shm->stats.madvise_cycler.failed,
				1, __ATOMIC_RELAXED);
			/* -EINVAL from MADV_COLLAPSE on
			 * non-THP-eligible ranges, -EAGAIN
			 * from MADV_FREE on a memory-
			 * pressured swapless system, etc.
			 * Expected; fall through. */
		}

		if (RAND_BOOL())
			touch_subrange(
				(volatile unsigned char *)
					ctx->region + offset,
				len);

		if (budget_elapsed_ns(&ctx->start, BUDGET_NS))
			break;
	}
}

/*
 * Phase 5: tear down what arm_guard set up, in reverse order: restore
 * the prior SIGSEGV / SIGBUS dispositions first so any post-disarm
 * fault routes back to child_fault_handler, then clear the bounds the
 * handler reads (a stray late signal hitting the just-restored handler
 * is harmless; one hitting our own handler with stale bounds could
 * siglongjmp into a vanished wrap).  Bump the pool_race_aborted stat
 * iff the wrap landed via siglongjmp -- this op holds no per-iteration
 * allocations, so there is no cleanup the abort path skipped; the
 * counter is observability, not error reporting (the outer return
 * stays true, matching the single-page early-return shape: "no useful
 * work, but not a dispatch-level failure").
 */
static void madvise_cycler_iter_disarm_guard(const struct sigaction *old_segv,
					     const struct sigaction *old_bus,
					     bool aborted)
{
	sigaction(SIGSEGV, old_segv, NULL);
	sigaction(SIGBUS,  old_bus,  NULL);

	madvise_cycler_pool_race_addr_low  = 0;
	madvise_cycler_pool_race_addr_high = 0;

	if (aborted)
		__atomic_add_fetch(
			&shm->stats.pool_race_aborted[CHILD_OP_MADVISE_CYCLER],
			1, __ATOMIC_RELAXED);
}

bool madvise_cycler(struct childdata *child)
{
	struct madvise_cycler_iter_ctx ictx = { 0 };
	/* volatile: iter_cap is computed before sigsetjmp via the BUDGETED
	 * macro (which contains a statement-expression temp _b) and read
	 * inside the wrap.  Without volatile GCC's -Wclobbered analysis
	 * flags _b as possibly-clobbered by longjmp; ISO C 7.13.2.1 only
	 * guarantees post-longjmp values for objects with volatile-
	 * qualified type. */
	volatile unsigned int iter_cap;
	int rc;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	__atomic_add_fetch(&shm->stats.madvise_cycler.runs, 1, __ATOMIC_RELAXED);

	rc = madvise_cycler_iter_pick_region(&ictx);
	if (rc < 0)
		return false;
	if (rc > 0)
		return true;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	madvise_cycler_iter_setup_budget(&ictx);

	iter_cap = BUDGETED(CHILD_OP_MADVISE_CYCLER,
			    JITTER_RANGE(MAX_ITERATIONS));

	{
		struct sigaction old_segv, old_bus;
		bool aborted = false;

		madvise_cycler_iter_arm_guard(&ictx, &old_segv, &old_bus);

		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);

		if (sigsetjmp(madvise_cycler_pool_race_jmp, 1) == 0)
			madvise_cycler_iter_run_cycle(&ictx, iter_cap);
		else
			aborted = true;

		madvise_cycler_iter_disarm_guard(&old_segv, &old_bus, aborted);
	}

	return true;
}
