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
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>

#include "arch.h"
#include "pids.h"
#include "child.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/mman.h"
/*
 * Pool-race fault guard.  See the comment on pool_race_aborted[] in
 * include/stats.h for the race we're catching.  The guard only
 * siglongjmps on real kernel faults (si_code > 0) whose si_addr
 * falls inside the pool mapping range drawn by this invocation.
 * Anything else falls through to the default handler so the per-pid
 * bug log path in signals.c child_fault_handler still gets reached:
 *
 *   - Sibling-spoofed fatal signals (si_code <= 0, si_pid != getpid)
 *     return silently — kernel already consumed the signal and we
 *     don't want to count spoof noise.
 *   - Self-sent fatal signals (si_code <= 0, si_pid == getpid, e.g.
 *     glibc abort) restore SIG_DFL and re-raise so child_fault_handler
 *     diagnoses + exits.  Don't siglongjmp here: glibc may hold the
 *     allocator lock and longjmping orphans it (see signals.c
 *     long-form rationale on the sigalrm_handler longjmp removal).
 *   - Real kernel faults whose si_addr is outside the drawn pool
 *     range (ASAN redzone hits, genuine SIGBUS on an unrelated mmap,
 *     a setup-path bug, etc.) restore SIG_DFL and re-raise so the
 *     bug log path is preserved.  This is the gate that the
 *     follow-up commit added: the prior wrap accepted any
 *     si_code > 0 as pool race, swallowing unrelated kernel faults.
 *   - Real kernel faults whose si_addr is inside the drawn pool
 *     range siglongjmp to the wrap epilogue, which bumps
 *     pool_race_aborted[] and returns false.
 *
 * The pool-mapping range is captured into the file-scope statics
 * below by the wrap site after the get_map_with_prot draw; the
 * handler reads them.  Writers publish via __atomic_store_n with
 * RELEASE on the addr_high half of the pair; the handler observes
 * via __atomic_load_n with ACQUIRE on the same half then RELAXED
 * on addr_low, so a kernel fault delivered mid-publish either sees
 * the fully-installed [low, high) range (and may siglongjmp) or
 * sees a stale range (and re-raises).  No "low updated, high not"
 * window for the handler to mis-classify into.
 *
 * Re-entry: sa_mask blocks SIGSEGV and SIGBUS for the duration of
 * the handler.  Without that, a SIGBUS arriving inside the SIGSEGV
 * handler invokes the same function recursively on the kernel signal
 * stack, and the inner siglongjmp unwinds past the outer handler's
 * frame without sigreturn — leaving the kernel-side handler-active
 * accounting half-installed for the lifetime of the wrap.  Blocking
 * both signals serialises handler invocations on this thread.
 *
 * old_segv / old_bus are file-scope statics rather than wrap-site
 * automatics so their values survive the longjmp without needing
 * volatile qualification on a struct that sigaction() takes by
 * non-volatile pointer.  memory_pressure() is single-call per
 * process so the non-reentrancy is not a constraint here.
 */
static sigjmp_buf memory_pressure_pool_race_jmp;
static uintptr_t memory_pressure_pool_race_addr_low;
static uintptr_t memory_pressure_pool_race_addr_high;
static struct sigaction memory_pressure_pool_race_old_segv;
static struct sigaction memory_pressure_pool_race_old_bus;

static __attribute__((no_sanitize("address")))
void memory_pressure_pool_race_handler(int sig, siginfo_t *info,
					      void *ctx)
{
	uintptr_t fault_addr, range_low, range_high;

	(void)ctx;
	if (info->si_code <= 0 && info->si_pid != mypid()) {
		/* Sibling-spoofed fatal signal — kernel already consumed
		 * it; return silently so the counter stays clean of
		 * signal-storm noise. */
		return;
	}
	if (info->si_code <= 0) {
		/* Self-sent (glibc abort etc.) — restore default and
		 * re-raise so child_fault_handler diagnoses + exits. */
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}

	fault_addr = (uintptr_t)info->si_addr;
	/* ACQUIRE on addr_high pairs with the wrap site's RELEASE store;
	 * a publish observable here guarantees the addr_low RELAXED load
	 * below sees the matching half of the [low, high) pair. */
	range_high = __atomic_load_n(&memory_pressure_pool_race_addr_high,
				     __ATOMIC_ACQUIRE);
	range_low = __atomic_load_n(&memory_pressure_pool_race_addr_low,
				    __ATOMIC_RELAXED);
	if (fault_addr < range_low || fault_addr >= range_high) {
		/* Real kernel fault but si_addr is outside the drawn
		 * pool range — not the race we're guarding against.
		 * Restore default and re-raise so child_fault_handler
		 * diagnoses + exits and the bug log path is preserved. */
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

	__atomic_add_fetch(&shm->stats.memory_pressure.runs, 1, __ATOMIC_RELAXED);

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	/* Setup is outside the wrap.  region/len/p/stride are derived from
	 * pointer arithmetic that cannot fault on the pool mapping itself,
	 * and any fault inside this setup region (e.g. m->ptr corruption)
	 * is not a pool race and should reach child_fault_handler via the
	 * default handler. */
	region = m->ptr;
	len = m->size;
	p = (volatile unsigned char *)region;
	stride = 3 * page_size;

	{
		struct sigaction sa;
		bool aborted = false;

		/* sigsetjmp captures the jmp_buf before sigaction installs
		 * the handler.  Reversing this order leaves a window where
		 * the handler is live but jmp_buf still points at a stack
		 * frame from a previous memory_pressure() invocation; a
		 * fault delivered in that window siglongjmps to a dead
		 * frame and restores sp/bp to stale values, which the
		 * subsequent code path then writes through.  Capturing
		 * first means any pool-range fault after install
		 * siglongjmps to the current-call epilogue below. */
		if (sigsetjmp(memory_pressure_pool_race_jmp, 1) == 0) {
			/* RELEASE on addr_high pairs with the handler's
			 * ACQUIRE load: a handler that observes the new
			 * addr_high is guaranteed to see the matching
			 * addr_low.  Publish before sigaction so the
			 * handler's first possible invocation already
			 * sees the [low, high) range. */
			__atomic_store_n(&memory_pressure_pool_race_addr_low,
					 (uintptr_t)region, __ATOMIC_RELAXED);
			__atomic_store_n(&memory_pressure_pool_race_addr_high,
					 (uintptr_t)region + len,
					 __ATOMIC_RELEASE);

			memset(&sa, 0, sizeof(sa));
			sigemptyset(&sa.sa_mask);
			sigaddset(&sa.sa_mask, SIGSEGV);
			sigaddset(&sa.sa_mask, SIGBUS);
			sa.sa_flags = SA_SIGINFO;
			sa.sa_sigaction = memory_pressure_pool_race_handler;
			sigaction(SIGSEGV, &sa,
				  &memory_pressure_pool_race_old_segv);
			sigaction(SIGBUS,  &sa,
				  &memory_pressure_pool_race_old_bus);

			if (valid_op)
				__atomic_add_fetch(
					&shm->stats.childop.data_path[op],
					1, __ATOMIC_RELAXED);

			/*
			 * Dirty each page so MADV_PAGEOUT has real work to do.
			 * Without this the pages are zero-filled and the
			 * kernel may skip the eviction (clean anonymous pages
			 * can simply be discarded rather than written to swap,
			 * which bypasses the reclaim writeback paths we want
			 * to hit).
			 */
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
			for (i = 0; i < len; i += stride)
				(void)p[i];
		} else {
			aborted = true;
		}

		sigaction(SIGSEGV, &memory_pressure_pool_race_old_segv, NULL);
		sigaction(SIGBUS,  &memory_pressure_pool_race_old_bus,  NULL);

		__atomic_store_n(&memory_pressure_pool_race_addr_low, 0,
				 __ATOMIC_RELAXED);
		__atomic_store_n(&memory_pressure_pool_race_addr_high, 0,
				 __ATOMIC_RELAXED);

		if (aborted) {
			/* siglongjmp skipped any in-flight cleanup —
			 * the in-flight allocation leak is accepted
			 * per the dispatch tradeoff. */
			__atomic_add_fetch(
				&shm->stats.childop.pool_race_aborted[CHILD_OP_MEMORY_PRESSURE],
				1, __ATOMIC_RELAXED);
			return false;
		}
	}

	return true;
}
