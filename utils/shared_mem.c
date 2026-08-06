#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "debug.h"
#include "locks.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"
#include "shared_mem-internal.h"

/*
 * Use this allocator if you have an object a child writes to that you want
 * all other processes to see.
 *
 * Every allocation is tracked so that VM syscalls (munmap, madvise, mremap,
 * mprotect) can avoid clobbering trinity's own shared state.
 */

/*
 * shared_regions[] fields (addr, size, and under CONFIG_GUARD_SHARED
 * the guarded flag and origin tag) are declared as struct
 * shared_region_entry in include/utils-internal.h so the range_overlap
 * cluster can read the same layout without duplicating the definition.
 * The definition lives here as the authoritative registry.
 */
struct shared_region_entry shared_regions[MAX_SHARED_ALLOCS];
unsigned int nr_shared_regions;

/*
 * Bounded overflow tail for registrations that arrive once
 * shared_regions[] is full.  Exists so range_overlaps_shared() (via the
 * bitmap, which is still updated) and range_in_tracked_shared() (via the
 * linear walk extension below) keep protecting fuzzed mm syscalls from
 * clobbering the untracked region instead of silently failing open.
 *
 * Intentionally small: 256 slots is "absorb a moderately over-budget
 * fleet host long enough to fail loudly and tell the operator to raise
 * MAX_SHARED_ALLOCS or move to dynamic resize", not "a second pool to
 * keep growing into".  Exhausting the tail BUG()s in both debug and
 * release; under-protection of a writable shared mapping is the failure
 * class the whole tracker exists to prevent and is never preferable to
 * a loud abort.
 */
/*
 * SHARED_REGIONS_OVERFLOW_TAIL and struct shared_region_entry are
 * declared in include/utils-internal.h so the range_overlap cluster
 * can walk the tail with the same layout as shared_regions[] above.
 */
struct shared_region_entry shared_regions_overflow[SHARED_REGIONS_OVERFLOW_TAIL];
unsigned int nr_shared_regions_overflow;

/*
 * Handle a registration that arrived once shared_regions[] is full.
 *
 * The previous "warn once, then silently drop the region" policy turned
 * an over-budget host into the exact failure mode this whole tracker
 * exists to prevent: range_overlaps_shared() can no longer guard an
 * untracked writable MAP_SHARED region from a fuzzed
 * munmap/mremap/madvise/mprotect, so the next call that picks an
 * unlucky address scribbles trinity's own shared state and the
 * resulting crash looks like a kernel bug.  Silent under-protection of
 * a writable shared mapping is never preferable to a loud abort.
 *
 * New policy, per call:
 *
 *   - Always emit a LOUD outputerr() naming the caller PC (resolved via
 *     pc_to_string, same idiom as log_mprotect_failure()), the offending
 *     region, and the tail occupancy.  Per-call (not cap-once): the
 *     cap-once predecessor hid how badly the cap was over budget, which
 *     is the one piece of data needed to size a real fix.
 *
 *   - Under ASAN (the developer / debug build), BUG() immediately --
 *     overflow is a tree-state bug and we want a stack trace, not a
 *     production-shaped degradation.
 *
 *   - In release, register the region in the bounded overflow tail so
 *     the bitmap stays correct (shared_bitmap_mark already covers the
 *     range) and range_in_tracked_shared() can still match precisely.
 *     Bump shm->stats.diag.shared_region_overflow so the over-budget state
 *     is visible in the periodic stats dump.
 *
 *   - If the overflow tail itself fills, BUG() in both debug and
 *     release.  Two layers of bounded storage is enough; a third would
 *     just be a slower path to the same silent-under-protection bug.
 */
static void register_shared_overflow(const char *who, unsigned long addr,
				     unsigned long size,
#ifdef CONFIG_GUARD_SHARED
				     bool guarded,
				     const char *origin,
#endif
				     void *caller)
{
	char pcbuf[128];

	outputerr("shared_regions: %s overflow: region 0x%lx+0x%lx from %s; "
		  "MAX_SHARED_ALLOCS=%d exhausted, overflow tail at %u/%d -- "
		  "raise the cap or move shared_regions[] to dynamic resize\n",
		  who, addr, size,
		  pc_to_string(caller, pcbuf, sizeof(pcbuf)),
		  MAX_SHARED_ALLOCS,
		  nr_shared_regions_overflow, SHARED_REGIONS_OVERFLOW_TAIL);

#ifdef __SANITIZE_ADDRESS__
#ifdef CONFIG_GUARD_SHARED
	(void)guarded;
	(void)origin;
#endif
	BUG("shared_regions[] overflow (debug build)");
#else
	if (nr_shared_regions_overflow >= SHARED_REGIONS_OVERFLOW_TAIL) {
		outputerr("shared_regions: overflow tail also exhausted "
			  "(%d slots); refusing to leave region 0x%lx+0x%lx "
			  "untracked\n",
			  SHARED_REGIONS_OVERFLOW_TAIL, addr, size);
		BUG("shared_regions overflow tail exhausted");
	}

	shared_regions_overflow[nr_shared_regions_overflow].addr = addr;
	shared_regions_overflow[nr_shared_regions_overflow].size = size;
#ifdef CONFIG_GUARD_SHARED
	shared_regions_overflow[nr_shared_regions_overflow].guarded =
		guarded ? 1 : 0;
	shared_regions_overflow[nr_shared_regions_overflow].origin = origin;
#endif
	shared_bitmap_mark(addr, size);
	tracked_size_mark(size);
	nr_shared_regions_overflow++;

	if (shm != NULL)
		__atomic_add_fetch(&shm->stats.diag.shared_region_overflow, 1,
				   __ATOMIC_RELAXED);
#endif
}

#ifdef CONFIG_GUARD_SHARED
/*
 * Primary shared-region allocator under CONFIG_GUARD_SHARED.  is_pool
 * tags long-lived regions (kcov_shm, shared str heap, childdata) so
 * --guard-shared=pools picks them up without dragging every per-child
 * tiny alloc into the VMA budget.  alloc_shared() below is the no-pool
 * entry point most call sites use; the three pool sites call
 * alloc_shared_pool() (a thin wrapper) which routes here with
 * is_pool=true.
 *
 * Behaviour matrix:
 *
 *   scope == OFF             -> single-mmap path (one runtime branch,
 *                               no extra syscalls).
 *   scope covers is_pool     -> guarded layout from guard_pages_alloc();
 *                               a guard-alloc failure logs and falls
 *                               back to the non-guarded path so the
 *                               run continues.
 *
 * Either path registers the INNER (ret, size) with shared_regions[] and
 * the bitmap; the guard pages are deliberately NOT tracked so the mm-
 * syscall sanitisers don't reject fuzzed calls against unrelated VA
 * that happens to share a 2 MiB bitmap chunk with a guard.  free_shared
 * inverts the layout via the guarded flag stored alongside.
 */
void * __alloc_shared(size_t size, bool is_pool)
{
	void *ret;
	bool guarded = false;

	if (guard_scope_covers(is_pool)) {
		ret = guard_pages_alloc(size);
		if (ret != MAP_FAILED)
			guarded = true;
	} else {
		ret = MAP_FAILED;
	}

	if (ret == MAP_FAILED) {
		ret = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_ANON | MAP_SHARED, -1, 0);
	}
	if (ret == MAP_FAILED) {
		outputerr("mmap %zu failure\n", size);
		exit(EXIT_FAILURE);
	}
	/* poison with independently-random bytes to expose uninitialized reads. */
	{
		unsigned char *p = ret;
		size_t i;

		for (i = 0; i + sizeof(unsigned int) <= size; i += sizeof(unsigned int)) {
			unsigned int r = rnd_u32();
			memcpy(p + i, &r, sizeof(r));
		}
		for (; i < size; i++)
			p[i] = (unsigned char)rnd_u32();
	}

	if (nr_shared_regions < MAX_SHARED_ALLOCS) {
		shared_regions[nr_shared_regions].addr = (unsigned long) ret;
		shared_regions[nr_shared_regions].size = size;
		shared_regions[nr_shared_regions].guarded = guarded ? 1 : 0;
		shared_regions[nr_shared_regions].origin = NULL;
		shared_bitmap_mark((unsigned long) ret, size);
		tracked_size_mark(size);
		nr_shared_regions++;
	} else {
		register_shared_overflow("alloc_shared", (unsigned long) ret,
					 size, guarded, NULL,
					 __builtin_return_address(0));
	}

	return ret;
}

void * alloc_shared(size_t size)
{
	return __alloc_shared(size, false);
}

void * alloc_shared_pool(size_t size)
{
	return __alloc_shared(size, true);
}

/*
 * Inverse of __alloc_shared().  Removes the matching shared_regions[]
 * slot, then munmaps either the full guarded span (PAGE + pages + PAGE
 * derived from the stored size+guarded flag) or the legacy (ret, size)
 * range.  No current alloc_shared caller has a destructor -- all pool
 * regions live for the parent's lifetime -- but the symmetry is the
 * spec contract for free-path correctness, and a future caller that
 * needs to release a pool region (test harness, lifecycle rework) must
 * route through here so the guard VMAs are not leaked behind.  Misses
 * silently to match untrack_shared_region()'s tolerance for callers
 * whose alloc was a no-op (size==0) or whose addr+size pair never
 * matched a registered slot exactly.
 */
void free_shared(void *p, size_t size)
{
	void *base = p;
	size_t span = size;
	bool guarded = false;
	unsigned int i;

	if (p == NULL)
		return;

	for (i = 0; i < nr_shared_regions; i++) {
		if (shared_regions[i].addr != (unsigned long)p ||
		    shared_regions[i].size != size)
			continue;
		guarded = shared_regions[i].guarded != 0;
		break;
	}
	if (i == nr_shared_regions) {
		for (i = 0; i < nr_shared_regions_overflow; i++) {
			if (shared_regions_overflow[i].addr != (unsigned long)p ||
			    shared_regions_overflow[i].size != size)
				continue;
			guarded = shared_regions_overflow[i].guarded != 0;
			break;
		}
	}

	untrack_shared_region((unsigned long)p, size);

	if (guarded)
		guard_pages_derive_span(p, size, &base, &span);

	if (munmap(base, span) != 0)
		outputerr("free_shared: munmap(%p, %zu) failed: errno=%d\n",
			  base, span, errno);
}

#else	/* !CONFIG_GUARD_SHARED */

/*
 * Legacy single-mmap path.  Byte-identical to pre-guard-armor trinity.
 */
void * alloc_shared(size_t size)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED) {
		outputerr("mmap %zu failure\n", size);
		exit(EXIT_FAILURE);
	}
	/* poison with independently-random bytes to expose uninitialized reads. */
	{
		unsigned char *p = ret;
		size_t i;

		for (i = 0; i + sizeof(unsigned int) <= size; i += sizeof(unsigned int)) {
			unsigned int r = rnd_u32();
			memcpy(p + i, &r, sizeof(r));
		}
		for (; i < size; i++)
			p[i] = (unsigned char)rnd_u32();
	}

	if (nr_shared_regions < MAX_SHARED_ALLOCS) {
		shared_regions[nr_shared_regions].addr = (unsigned long) ret;
		shared_regions[nr_shared_regions].size = size;
		shared_bitmap_mark((unsigned long) ret, size);
		tracked_size_mark(size);
		nr_shared_regions++;
	} else {
		register_shared_overflow("alloc_shared", (unsigned long) ret,
					 size, __builtin_return_address(0));
	}

	return ret;
}

#endif	/* CONFIG_GUARD_SHARED */

/*
 * Add an externally-mmap'd region to the shared_regions tracker so the
 * range_overlaps_shared() guards in the mm-syscall sanitisers refuse
 * fuzzed munmap/mremap/madvise/mprotect calls that target it.  Used by
 * code that mmaps via something other than alloc_shared() and still
 * needs the region protected from the fuzzer -- e.g., the per-child
 * kcov ring buffer mapped from /sys/kernel/debug/kcov.
 */
/*
 * Shared register-with-optional-origin core.  Plain track_shared_region
 * forwards origin=NULL so the existing call sites stay byte-identical;
 * track_shared_region_tagged plumbs through a short string used by the
 * diagnostic audit (range_overlaps_shared_slow) and the in-handler
 * dumps to name the offending region.
 */
static void track_shared_region_inner(unsigned long addr, unsigned long size,
				      const char *origin)
{
	if (nr_shared_regions < MAX_SHARED_ALLOCS) {
		shared_regions[nr_shared_regions].addr = addr;
		shared_regions[nr_shared_regions].size = size;
#ifdef CONFIG_GUARD_SHARED
		/* Externally-mmap'd, never guarded by __alloc_shared. */
		shared_regions[nr_shared_regions].guarded = 0;
		shared_regions[nr_shared_regions].origin = origin;
#else
		(void) origin;
#endif
		shared_bitmap_mark(addr, size);
		tracked_size_mark(size);
		nr_shared_regions++;
	} else {
		register_shared_overflow("track_shared_region", addr, size,
#ifdef CONFIG_GUARD_SHARED
					 false, origin,
#endif
					 __builtin_return_address(0));
	}
}

void track_shared_region(unsigned long addr, unsigned long size)
{
	track_shared_region_inner(addr, size, NULL);
}

#ifdef CONFIG_GUARD_SHARED
void track_shared_region_tagged(unsigned long addr, unsigned long size,
				const char *origin)
{
	track_shared_region_inner(addr, size, origin);
}
#endif

/*
 * Inverse of track_shared_region() / alloc_shared() registration.
 * Removes the matching shared_regions[] entry (exact addr+size match)
 * and undoes the bitmap refcount/bit it contributed, so providers that
 * munmap their region on destructor (io_uring rings, kvm vCPU run
 * pages) stop accumulating stale slots and stop holding the bitmap bit
 * set after their VA has been recycled to something unrelated.
 *
 * Slot reuse uses swap-with-last compaction: the freed slot inherits
 * the array tail, nr_shared_regions decrements.  Nothing depends on
 * shared_regions[] order beyond shared_bitmap_self_check() peeking at
 * slot 0, and that runs once at init -- well before any destructor can
 * fire -- so the order disturbance is invisible to live code paths
 * (range_overlaps_shared and range_in_tracked_shared both walk the
 * whole array).
 *
 * Walks the overflow tail too: a provider whose registration was
 * parked there is no less tracked from the caller's perspective and
 * must be unregistered the same way; otherwise the tail would only
 * ever grow.
 *
 * A miss returns silently rather than BUG()ing: a caller may
 * legitimately untrack a region whose original track call was a no-op
 * (e.g. size==0), or whose addr+size pair doesn't exactly match a
 * registration (the slot allocator is exact-match only).  Silent miss
 * is the same shape as Linux's __ClearPageReserved on a non-Reserved
 * page -- the inverse of a "best effort" registration is best effort.
 */
void untrack_shared_region(unsigned long addr, unsigned long size)
{
	unsigned int i;

	for (i = 0; i < nr_shared_regions; i++) {
		if (shared_regions[i].addr != addr ||
		    shared_regions[i].size != size)
			continue;
		shared_bitmap_unmark(addr, size);
		tracked_size_unmark(size);
		shared_regions[i] = shared_regions[nr_shared_regions - 1];
		nr_shared_regions--;
		return;
	}

	for (i = 0; i < nr_shared_regions_overflow; i++) {
		if (shared_regions_overflow[i].addr != addr ||
		    shared_regions_overflow[i].size != size)
			continue;
		shared_bitmap_unmark(addr, size);
		tracked_size_unmark(size);
		shared_regions_overflow[i] =
			shared_regions_overflow[nr_shared_regions_overflow - 1];
		nr_shared_regions_overflow--;
		return;
	}
}

/*
 * Dedicated allocator for shared regions whose start MUST be page
 * aligned.  The general alloc_shared_pool() path under CONFIG_GUARD_
 * SHARED with --guard-shared=pools routes through guard_pages_alloc(),
 * which END-aligns the inner buffer against the trailing guard.  A
 * consumer that later calls mprotect() on the region -- freeze_sibling_
 * childdata over each sibling's childdata -- then hits mprotect's page-
 * boundary precondition on the start address and returns EINVAL.  The
 * silent failure left every sibling's childdata unprotected against
 * wild kernel writes, which was the mechanism behind the self-SIGSEGV
 * cluster in add_object / kcov_collect / addr_in_local_runtime_map.
 *
 * This path pins a page-aligned start unconditionally: the returned
 * mapping starts at an address mmap chose (page-aligned by
 * construction), spans inner_size rounded up to a page multiple, and
 * is registered with shared_regions[] using that same rounded length
 * so downstream mprotect() and range-guard queries see the true VMA
 * footprint.  Guard pages are deliberately not layered on -- losing
 * the trailing-guard trap for this region is the trade for having a
 * working freeze, which is the primary defence for callers that route
 * here.
 *
 * *out_rounded_len is written before return so the freeze site can
 * mprotect exactly the span the mapping covers -- passing raw
 * inner_size to mprotect works too (the kernel rounds up), but keeping
 * the two lengths locked together makes the "same span" contract
 * self-evident and lets range_in_tracked_shared / free_shared match
 * without arithmetic.
 */
void *alloc_shared_page_aligned(size_t inner_size, size_t *out_rounded_len)
{
	size_t rounded;
	void *ret;
	unsigned char *p;
	size_t i;

	if (inner_size == 0 || page_size == 0) {
		outputerr("alloc_shared_page_aligned: bad args inner=%zu page_size=%u\n",
			  inner_size, (unsigned int)page_size);
		exit(EXIT_FAILURE);
	}

	rounded = (inner_size + (size_t)page_size - 1) & (size_t)PAGE_MASK;

	ret = mmap(NULL, rounded, PROT_READ | PROT_WRITE,
		   MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED) {
		outputerr("alloc_shared_page_aligned: mmap %zu failure\n",
			  rounded);
		exit(EXIT_FAILURE);
	}

	/* Poison with random bytes to expose uninitialised reads, matching
	 * alloc_shared()'s post-mmap poison so the two allocation paths
	 * present the same "clear-before-use" contract to consumers. */
	p = ret;
	for (i = 0; i + sizeof(unsigned int) <= rounded;
	     i += sizeof(unsigned int)) {
		unsigned int r = rnd_u32();
		memcpy(p + i, &r, sizeof(r));
	}
	for (; i < rounded; i++)
		p[i] = (unsigned char)rnd_u32();

	track_shared_region((unsigned long)ret, rounded);

	if (out_rounded_len != NULL)
		*out_rounded_len = rounded;
	return ret;
}

bool shared_size_mul(size_t a, size_t b, size_t *out)
{
	return !__builtin_mul_overflow(a, b, out);
}
