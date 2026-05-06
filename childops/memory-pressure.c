/*
 * memory_pressure - madvise(MADV_PAGEOUT) + refault to exercise OOM-adjacent
 * kernel paths.
 *
 * Evicting a large anonymous region forces the kernel to walk the LRU,
 * deactivate pages, and write them to the swap device (or zram/zswap).
 * Immediately reading the region back triggers page faults that must
 * allocate new physical pages, invoke the page fault handler, and re-read
 * from swap — exactly the allocation/rollback paths that are often reached
 * only under genuine memory pressure and that frequently contain incomplete
 * error handling or locking assumptions that differ from the steady-state
 * path.  Running other syscall fuzzing concurrently (in sibling children)
 * while these refaults are in flight further increases the chance of hitting
 * mid-allocation failure modes.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Pool-race fault guard.  See the comment on pool_race_aborted[] in
 * include/stats.h for the race we're catching.  The guard only
 * siglongjmps on real kernel faults (si_code > 0); sibling-spoofed
 * fatal signals are filtered the same way child_fault_handler filters
 * them in signals.c:80, and self-sent signals fall through to the
 * default handler (so a glibc abort still gets diagnosed by
 * child_fault_handler instead of orphaning the allocator lock — see
 * signals.c:175-184 for the long-form rationale).
 *
 * Wrap is currently inlined per-childop at 4 sites (memory_pressure,
 * iouring_flood, iouring_recipes, madvise_cycler).  TODO: if this
 * pattern grows past ~6 callsites, factor into childops-util.h as
 * childop_run_with_fault_guard().
 *
 * Per-childop wrap scope: cluster M only (sibling-driven UAF on
 * pool-drawn mappings).  Other childops are out of scope for this
 * change — they don't draw from the parent's mapping pool.
 */
static sigjmp_buf memory_pressure_pool_race_jmp;

static void memory_pressure_pool_race_handler(int sig, siginfo_t *info,
					      void *ctx)
{
	(void)ctx;
	if (info->si_code <= 0 && info->si_pid != getpid()) {
		/* Sibling-spoofed fatal signal — kernel already consumed
		 * it; return silently so the counter stays clean of
		 * signal-storm noise. */
		return;
	}
	if (info->si_code <= 0) {
		/* Self-sent (glibc abort etc.) — restore default and
		 * re-raise so child_fault_handler diagnoses + exits.
		 * Don't siglongjmp here: glibc may hold the allocator
		 * lock and longjmping orphans it. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}
	siglongjmp(memory_pressure_pool_race_jmp, 1);
}

bool memory_pressure(struct childdata *child)
{
	struct map *m;
	size_t len;
	void *region;
	volatile unsigned char *p;
	size_t stride, i;

	(void)child;

	/*
	 * Draw the region from the parent's inherited mapping pool instead
	 * of mmap()ing a fresh private allocation per invocation.  The pool
	 * is built once in the parent and shared COW into every child, so
	 * sibling memory_pressure invocations running concurrently will
	 * sometimes target the same physical pages — that convergence is
	 * the point: it amplifies LRU contention and exposes the
	 * eviction / refault race surface to multiple reclaimers at once,
	 * which is far harder to provoke with disjoint per-child regions.
	 *
	 * The pool is owned by the parent: do NOT munmap on cleanup.
	 * Tearing down a pool entry would unmap pages that every other
	 * sibling drawing the same map is still treating as live.
	 */
	m = get_map_with_prot(PROT_WRITE);
	if (m == NULL)
		return false;

	__atomic_add_fetch(&shm->stats.memory_pressure_runs, 1, __ATOMIC_RELAXED);

	{
		struct sigaction sa, old_segv, old_bus;
		bool aborted = false;

		memset(&sa, 0, sizeof(sa));
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO;
		sa.sa_sigaction = memory_pressure_pool_race_handler;
		sigaction(SIGSEGV, &sa, &old_segv);
		sigaction(SIGBUS,  &sa, &old_bus);

		if (sigsetjmp(memory_pressure_pool_race_jmp, 1) == 0) {
			region = m->ptr;
			len = m->size;

			/*
			 * Dirty each page so MADV_PAGEOUT has real work to do.
			 * Without this the pages are zero-filled and the
			 * kernel may skip the eviction (clean anonymous pages
			 * can simply be discarded rather than written to swap,
			 * which bypasses the reclaim writeback paths we want
			 * to hit).
			 */
			p = (volatile unsigned char *)region;
			for (i = 0; i < len; i += page_size)
				p[i] = (unsigned char)(i & 0xff);

			/* Evict: ask the kernel to reclaim the entire region.
			 * 1-in-RAND_NEGATIVE_RATIO sub the curated MADV_PAGEOUT
			 * advice for a curated edge value — exercises
			 * madvise_behavior_valid's unknown/negative advice
			 * rejection which the single MADV_* constant above
			 * never reaches. */
			madvise(region, len,
				(int)RAND_NEGATIVE_OR(MADV_PAGEOUT));

			/*
			 * Refault: read back one byte per page, forcing a
			 * page fault for each.  Walk with a stride larger
			 * than page_size to avoid triggering readahead for
			 * contiguous pages, so each fault is handled
			 * independently by the allocator.
			 */
			stride = 3 * page_size;
			for (i = 0; i < len; i += stride)
				(void)p[i];
		} else {
			aborted = true;
		}

		sigaction(SIGSEGV, &old_segv, NULL);
		sigaction(SIGBUS,  &old_bus,  NULL);

		if (aborted) {
			/* siglongjmp skipped any in-flight cleanup —
			 * the in-flight allocation leak is accepted
			 * per the dispatch tradeoff. */
			__atomic_add_fetch(
				&shm->stats.pool_race_aborted[CHILD_OP_MEMORY_PRESSURE],
				1, __ATOMIC_RELAXED);
			return false;
		}
	}

	return true;
}
