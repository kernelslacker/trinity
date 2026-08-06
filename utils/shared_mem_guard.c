/*
 * Guard-page debug mode for the shared-memory allocator.
 *
 * Compiled only when CONFIG_GUARD_SHARED is set.  Wraps alloc_shared()
 * regions with PROT_NONE leading/trailing pages so buffer overflows trap
 * at byte granularity in child_fault_handler rather than silently
 * corrupting adjacent shared state.
 *
 * guard_scope governs which allocations get the armour:
 *   OFF   - legacy single-mmap path (no extra VMAs)
 *   POOLS - long-lived pool regions (kcov_shm, str heap, childdata)
 *   ALL   - every alloc_shared() call
 *
 * guard_pages_alloc / guard_pages_derive_span / guard_scope_covers are
 * called from utils/shared_mem.c and are therefore non-static.
 * guard_pages_classify / guard_shared_scope_name / guard_shared_count_guarded
 * are the public API declared in include/utils-mem.h.
 */

#ifdef CONFIG_GUARD_SHARED

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include "debug.h"
#include "shm.h"
#include "trinity.h"
#include "utils-internal.h"
#include "shared_mem-internal.h"

/*
 * Runtime scope for the guard-page armour wired into __alloc_shared().
 * Initialised to GUARD_SCOPE_OFF; flipped to POOLS or ALL by parse_args()
 * when the operator passes --guard-shared[=pools|all].  Hot path:
 * __alloc_shared() reads this once per call.
 *
 *   OFF   - no guards, byte-identical to the legacy single-mmap path
 *           (modulo the runtime branch).  This is the production default.
 *   POOLS - guard only the long-lived regions tagged is_pool=true by
 *           their alloc site (kcov_shm, the shared str/obj heap, per-
 *           child childdata).  Bounded VMA cost, focused on the
 *           recurring corruption-witness clusters from the
 *           2026-06-08 triage runs.
 *   ALL   - guard every alloc_shared() region, pool or not.  VMA cost
 *           scales with MAX_SHARED_ALLOCS; intended for short-run
 *           investigations where the writer might not be in the pools
 *           subset.  Warns + suggests raising vm.max_map_count at the
 *           flag-parse site.
 *
 * Off → __alloc_shared() and free_shared() collapse to today's exact
 * mmap / unregister behaviour at runtime as well, so a build that
 * compiled CONFIG_GUARD_SHARED in stays production-safe until the
 * operator opts in.
 */
enum guard_scope guard_shared_scope = GUARD_SCOPE_OFF;

/*
 * Round len up to the nearest page boundary.  page_size is populated by
 * init_main_process() before parse_args() and any alloc_shared() caller,
 * so it is always non-zero by the time this is reachable.
 */
static size_t guard_pages_round_up(size_t len)
{
	size_t ps = (size_t)page_size;

	return (len + ps - 1) & ~(ps - 1);
}

/*
 * Recover (base, span) from the inner pointer + size of a guarded
 * region.  __alloc_shared() lays out a guarded mapping as
 *
 *   | leading guard (1 page) | unused fold | inner buffer | trailing guard (1 page) |
 *   ^base                     ^base+PAGE    ^ret           ^base+PAGE+pages
 *
 * with pages = round_up(size, page_size) and the inner buffer end-
 * aligned against the trailing guard so a forward overflow (buf[size])
 * traps at byte granularity.  Inverting:
 *
 *   pages = round_up(size, page_size)
 *   base  = ret - PAGE - (pages - size)
 *   span  = PAGE + pages + PAGE
 *
 * The size is stored in shared_regions[].size and the guarded bit is
 * stored alongside, so free_shared() needs no parallel side table to
 * unwind the layout.
 */
void guard_pages_derive_span(void *ret, size_t size,
				    void **base_out, size_t *span_out)
{
	size_t ps = (size_t)page_size;
	size_t pages = guard_pages_round_up(size);
	char *base = (char *)ret - ps - (pages - size);

	*base_out = base;
	*span_out = ps + pages + ps;
}

/*
 * Mmap a guarded region: one VA span = leading-guard + usable-pages +
 * trailing-guard, with the inner buffer end-aligned against the
 * trailing guard.  Returns the inner pointer (the address callers see
 * and store in shared_regions[]), or MAP_FAILED on failure.  On
 * failure logs a single outputerr() line and leaves no VMA behind:
 * the leading-guard mprotect is reverted by munmap before return so
 * the caller can fall back to a non-guarded mmap without leaking VA.
 */
void *guard_pages_alloc(size_t size)
{
	size_t ps = (size_t)page_size;
	size_t pages = guard_pages_round_up(size);
	size_t span = ps + pages + ps;
	char *base;

	base = mmap(NULL, span, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_SHARED, -1, 0);
	if (base == MAP_FAILED) {
		outputerr("guard_pages_alloc: mmap %zu failure (span=%zu)\n",
			  size, span);
		return MAP_FAILED;
	}

	/* Drop the leading and trailing pages to PROT_NONE so any
	 * adjacent overflow traps in copy_*_user (kernel-side) or
	 * directly at the writer PC (userspace).  Splits the span into
	 * three VMAs (guard / usable / guard); the cost is +2 VMAs per
	 * guarded region.
	 *
	 * Both mprotects run once per guarded region at setup time
	 * (alloc_shared is called from init paths, not from the arg-gen
	 * hot loop), so the slow-path checker's blanket ban does not
	 * apply -- mark explicitly to keep the surface honest.
	 */
	/* check-static: slow-ok */
	if (mprotect(base, ps, PROT_NONE) != 0) {
		outputerr("guard_pages_alloc: mprotect(leading) failed: errno=%d\n",
			  errno);
		(void)munmap(base, span);
		return MAP_FAILED;
	}
	/* check-static: slow-ok */
	if (mprotect(base + ps + pages, ps, PROT_NONE) != 0) {
		outputerr("guard_pages_alloc: mprotect(trailing) failed: errno=%d\n",
			  errno);
		(void)munmap(base, span);
		return MAP_FAILED;
	}

	/* End-align the inner buffer against the trailing guard so a
	 * forward overflow at byte granularity (buf[size] = x) faults
	 * at the writer PC instead of corrupting the fold region. */
	return base + ps + (pages - size);
}

/*
 * Decide whether this allocation falls into the current guard scope.
 * GUARD_SCOPE_OFF gates everything off (legacy fast path).
 * GUARD_SCOPE_POOLS guards only is_pool=true alloc sites (kcov_shm,
 * shared str heap, childdata -- the long-lived regions the corruption
 * clusters keep pointing at).  GUARD_SCOPE_ALL guards every site.
 */
bool guard_scope_covers(bool is_pool)
{
	switch (guard_shared_scope) {
	case GUARD_SCOPE_ALL:
		return true;
	case GUARD_SCOPE_POOLS:
		return is_pool;
	case GUARD_SCOPE_OFF:
	default:
		return false;
	}
}

/*
 * Classify a fault address against the guarded regions tracked in
 * shared_regions[].  Returns true and fills outs when @fault_addr
 * lands in either the leading or trailing PROT_NONE page abutting a
 * guarded region; false otherwise.
 *
 * Called from child_fault_handler() on every fatal-signal delivery
 * before the in-handler diagnostic path runs, so this MUST be async-
 * signal-safe: plain reads of file-scope arrays only -- no allocator,
 * no stdio, no lock, no libc call outside the POSIX 2024 sec 2.4.3 set.
 * shared_regions[] is published once at init time (single-threaded
 * parent context) and never mutated past first fork, so a child
 * handler observing it sees a stable snapshot.  The page_size global
 * is set in init_main_process(), also before any fork.
 *
 * @delta_out is the byte-distance from the fault address to the
 * nearest legitimate edge of the region: how far past the end for a
 * trailing-guard fault (fault_addr - region_end), or how far before
 * the start for a leading-guard fault (region_start - fault_addr - 1
 * mapped through 0).  Bounded by page_size by construction.
 */
bool guard_pages_classify(uintptr_t fault_addr,
			  uintptr_t *region_addr_out,
			  size_t *region_size_out,
			  bool *trailing_out,
			  unsigned long *delta_out)
{
	uintptr_t ps = (uintptr_t)page_size;
	uintptr_t leading_start, trailing_start;
	unsigned long pages;
	unsigned int i;

	if (ps == 0)
		return false;

	for (i = 0; i < nr_shared_regions; i++) {
		if (shared_regions[i].guarded == 0)
			continue;

		pages = (shared_regions[i].size + ps - 1) & ~(ps - 1);
		leading_start = shared_regions[i].addr - ps -
				(pages - shared_regions[i].size);
		trailing_start = shared_regions[i].addr +
				 shared_regions[i].size;
		/* trailing guard sits at base+PAGE+pages == addr+size +
		 * (pages - size); collapse via the layout invariant. */
		trailing_start = leading_start + ps + pages;

		if (fault_addr >= leading_start &&
		    fault_addr < leading_start + ps) {
			*region_addr_out = shared_regions[i].addr;
			*region_size_out = shared_regions[i].size;
			*trailing_out = false;
			*delta_out = (unsigned long)
				(shared_regions[i].addr - fault_addr);
			return true;
		}
		if (fault_addr >= trailing_start &&
		    fault_addr < trailing_start + ps) {
			*region_addr_out = shared_regions[i].addr;
			*region_size_out = shared_regions[i].size;
			*trailing_out = true;
			*delta_out = (unsigned long)
				(fault_addr -
				 (shared_regions[i].addr +
				  shared_regions[i].size));
			return true;
		}
	}

	for (i = 0; i < nr_shared_regions_overflow; i++) {
		if (shared_regions_overflow[i].guarded == 0)
			continue;

		pages = (shared_regions_overflow[i].size + ps - 1) & ~(ps - 1);
		leading_start = shared_regions_overflow[i].addr - ps -
				(pages - shared_regions_overflow[i].size);
		trailing_start = leading_start + ps + pages;

		if (fault_addr >= leading_start &&
		    fault_addr < leading_start + ps) {
			*region_addr_out = shared_regions_overflow[i].addr;
			*region_size_out = shared_regions_overflow[i].size;
			*trailing_out = false;
			*delta_out = (unsigned long)
				(shared_regions_overflow[i].addr - fault_addr);
			return true;
		}
		if (fault_addr >= trailing_start &&
		    fault_addr < trailing_start + ps) {
			*region_addr_out = shared_regions_overflow[i].addr;
			*region_size_out = shared_regions_overflow[i].size;
			*trailing_out = true;
			*delta_out = (unsigned long)
				(fault_addr -
				 (shared_regions_overflow[i].addr +
				  shared_regions_overflow[i].size));
			return true;
		}
	}

	return false;
}

/*
 * Name the current guard-shared scope for the startup banner.  Mirrors
 * the operator-facing spellings accepted by parse_args() so a log line
 * is grep-pasteable straight into a re-run command.  Stable string,
 * safe to call before parse_args (returns "off").
 */
const char *guard_shared_scope_name(void)
{
	switch (guard_shared_scope) {
	case GUARD_SCOPE_ALL:
		return "all";
	case GUARD_SCOPE_POOLS:
		return "pools";
	case GUARD_SCOPE_OFF:
	default:
		return "off";
	}
}

/*
 * Count shared_regions[] entries (plus the overflow tail) carrying a
 * set .guarded bit.  Matches the iteration in guard_pages_classify so
 * the banner's "(N regions guarded)" reads the same population the
 * fault-time classifier will see -- a zero here means no guard-page
 * VMA exists, even if the scope says POOLS / ALL.
 */
unsigned int guard_shared_count_guarded(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < nr_shared_regions; i++)
		if (shared_regions[i].guarded)
			n++;
	for (i = 0; i < nr_shared_regions_overflow; i++)
		if (shared_regions_overflow[i].guarded)
			n++;
	return n;
}

#endif	/* CONFIG_GUARD_SHARED */
