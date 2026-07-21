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

/*
 * Use this allocator if you have an object a child writes to that you want
 * all other processes to see.
 *
 * Every allocation is tracked so that VM syscalls (munmap, madvise, mremap,
 * mprotect) can avoid clobbering trinity's own shared state.
 */

#ifdef CONFIG_GUARD_SHARED
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
 *           recurring corruption-witness clusters from the 2026-06-08
 *           overnight triages.
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
#endif

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
 * Bitmap accelerator for range_overlaps_shared().  One bit per
 * SHARED_BITMAP_GRANULARITY-byte chunk of user VA; a set bit means at
 * least one byte in that chunk belongs to a registered shared region.
 *
 * The mm-syscall sanitisers (madvise/mremap/mprotect/munmap/mseal/mbind/
 * process_madvise/remap_file_pages/...) call range_overlaps_shared()
 * once per fuzzed call, often many times per child per second.  The
 * original linear scan over shared_regions[] is O(N) per query with N
 * easily reaching 100+ on a 32-child fleet (per-child childdata,
 * fd_event ring, kcov ring, plus the global reserve).  Replacing the
 * scan with this bitmap turns the hot path into one or two word loads
 * for the common single-page query.
 *
 * Granularity 2 MiB is the natural unit for the conservative
 * over-reject guarantee: any 2 MiB chunk that touches a shared region
 * gets its bit set, and a query whose footprint hits that chunk
 * rejects.  False positives are possible at chunk boundaries (a
 * non-shared page co-located in the same 2 MiB chunk as a shared
 * region rejects too), which is the SAFETY direction -- under-reject
 * would let a fuzzed mmap call clobber trinity's own shared state.
 *
 * Span 1<<47 covers the canonical x86_64 user VA on default
 * (4-level page table) kernels.  Regions registered outside the span
 * (5-level page tables, or unusually high mappings) are still recorded
 * in the authoritative shared_regions[]; shared_bitmap_mark() simply
 * no-ops for them and range_overlaps_shared() falls back to a linear
 * scan over shared_regions[] for above-span queries.  At 1 bit per
 * 2 MiB, the bitmap is
 * 1<<26 bits = 8 MiB of BSS, but it is mostly zero pages: only the
 * 4 KiB pages that cover actually-set bits ever fault in, so true
 * resident growth is in the kilobytes for a typical fleet host where
 * shared regions cluster in the mmap arena near 0x7f000000....
 */
/*
 * SHARED_BITMAP_* macros are declared in include/utils-internal.h so
 * the range_overlap cluster can index into shared_region_bitmap[]
 * with the same word/bit arithmetic used by the mark/unmark path.
 */
unsigned long shared_region_bitmap[SHARED_BITMAP_NWORDS];

/*
 * Per-chunk refcount paired with shared_region_bitmap above.  Multiple
 * tracked regions may live in the same 2 MiB chunk (every alloc_shared
 * call rounds up to a chunk for bitmap purposes; nothing forbids two
 * adjacent mmaps landing in the same chunk).  The bit must stay set
 * until the LAST tracked region in the chunk is removed -- clearing it
 * on the first untrack would flip the safety invariant from
 * "over-reject" to "under-reject" for the surviving region in the
 * chunk, exactly the failure mode this whole guard exists to prevent.
 *
 * uint16_t covers the worst-case occupancy by a comfortable margin
 * (MAX_SHARED_ALLOCS + overflow tail = 4352 << 65535) and bumps BSS
 * from 8 MiB (the bitmap alone) to 8 MiB + 128 MiB.  Same lazy-faulting
 * argument as the bitmap: only chunks touched by registrations ever
 * fault their backing page in, so true resident growth stays in the
 * tens of KiB for the typical clustered fleet-host layout.
 */
static uint16_t shared_region_refcount[SHARED_BITMAP_NBITS];

static inline bool shared_bitmap_test(unsigned long bit)
{
	return (shared_region_bitmap[bit / SHARED_BITMAP_BITS_PER_WORD] >>
		(bit % SHARED_BITMAP_BITS_PER_WORD)) & 1UL;
}

static inline void shared_bitmap_set(unsigned long bit)
{
	shared_region_bitmap[bit / SHARED_BITMAP_BITS_PER_WORD] |=
		1UL << (bit % SHARED_BITMAP_BITS_PER_WORD);
}

static inline void shared_bitmap_clear(unsigned long bit)
{
	shared_region_bitmap[bit / SHARED_BITMAP_BITS_PER_WORD] &=
		~(1UL << (bit % SHARED_BITMAP_BITS_PER_WORD));
}

/*
 * Mark every 2 MiB chunk that intersects [addr, addr+size).  Called
 * from the tail of alloc_shared() and track_shared_region() so the
 * bitmap stays in sync with shared_regions[].  size==0 is a no-op
 * (matches the "empty region overlaps nothing" semantics callers rely
 * on).  An out-of-span (or span-straddling) registration is a no-op
 * here: the bitmap only covers [0, SHARED_BITMAP_VA_SPAN), but
 * shared_regions[] is the authoritative registry and registration
 * already recorded the region there.  The query path falls back to a
 * linear scan over shared_regions[] for addresses the bitmap can't
 * cover, so the safety invariant ("no fuzzed mm syscall clobbers a
 * tracked region") still holds.
 */
static void shared_bitmap_mark(unsigned long addr, unsigned long size)
{
	unsigned long end, first, last, bit;

	if (size == 0)
		return;

	if (addr >= SHARED_BITMAP_VA_SPAN ||
	    size > SHARED_BITMAP_VA_SPAN - addr)
		return;

	end = addr + size - 1;
	first = addr >> SHARED_BITMAP_GRANULARITY_LOG2;
	last = end >> SHARED_BITMAP_GRANULARITY_LOG2;

	for (bit = first; bit <= last; bit++) {
		if (shared_region_refcount[bit] == UINT16_MAX) {
			outputerr("shared_bitmap_mark: refcount overflow at "
				  "chunk %lu for region 0x%lx+0x%lx\n",
				  bit, addr, size);
			BUG("shared region refcount overflow");
		}
		shared_region_refcount[bit]++;
		shared_bitmap_set(bit);
	}
}

/*
 * Inverse of shared_bitmap_mark().  Decrements the per-chunk refcount
 * for every 2 MiB chunk the range spans and clears the bitmap bit only
 * once the chunk's last tracked region is gone.  Called from
 * untrack_shared_region() after a matching shared_regions[] slot has
 * been located, so an inconsistency (refcount==0 on a chunk the caller
 * believes it tracked) is a tree-state bug worth BUG()ing on rather
 * than silently masking -- a stuck bit with refcount==0 would falsely
 * reject every fuzzed mm syscall touching the chunk forever.  An
 * out-of-span (or span-straddling) unmark is a no-op for the same
 * reason mark() no-ops above the span: the bitmap doesn't track those
 * addresses, so there is nothing to clear.
 */
static void shared_bitmap_unmark(unsigned long addr, unsigned long size)
{
	unsigned long end, first, last, bit;

	if (size == 0)
		return;

	if (addr >= SHARED_BITMAP_VA_SPAN ||
	    size > SHARED_BITMAP_VA_SPAN - addr)
		return;

	end = addr + size - 1;
	first = addr >> SHARED_BITMAP_GRANULARITY_LOG2;
	last = end >> SHARED_BITMAP_GRANULARITY_LOG2;

	for (bit = first; bit <= last; bit++) {
		if (shared_region_refcount[bit] == 0) {
			outputerr("shared_bitmap_unmark: refcount underflow at "
				  "chunk %lu for region 0x%lx+0x%lx\n",
				  bit, addr, size);
			BUG("shared region refcount underflow");
		}
		if (--shared_region_refcount[bit] == 0)
			shared_bitmap_clear(bit);
	}
}

/*
 * Size-bucket bitmap accelerator for range_overlaps_shared(): companion
 * to the address-keyed shared_region_bitmap above.  Bit i is set
 * whenever at least one tracked shared region currently falls into
 * size bucket i, where bucket i = floor(log2(len)) and covers regions
 * of len in [2^i, 2^(i+1)).  An empty bitmap (no tracked region of any
 * size) is the useful negative the address bitmap has to discover one
 * word at a time: one load here short-circuits the SHARED_BITMAP_NWORDS
 * word-scan over a multi-MiB query, plus the downstream byte-precise
 * walk that confirms a bitmap hit.
 *
 * Distinct concern from shared_region_bitmap above.  That bitmap
 * encodes WHERE tracked regions live (one bit per 2 MiB chunk of user
 * VA); this one encodes only WHETHER any tracked region exists in each
 * size class.  The two are wired in pairs: every register
 * (alloc_shared, track_shared_region, register_shared_overflow) calls
 * shared_bitmap_mark() AND tracked_size_mark(); every untrack (the
 * regular slot AND the overflow tail path in untrack_shared_region)
 * calls shared_bitmap_unmark() AND tracked_size_unmark().  Forgetting
 * the parallel call in a future refactor flips the size bitmap's
 * safety invariant from "empty ⇒ provably no regions" to "empty ⇒
 * silently under-reject"; shared_bitmap_self_check() asserts the
 * positive-path wiring at startup so that class of bug fails loudly.
 *
 * 64 buckets is the natural cap: a single unsigned long stores the
 * whole bitmap, and SHARED_BITMAP_VA_SPAN = 1<<47 bounds the largest
 * possible region at bucket 47 anyway -- buckets 48..63 stay zero on
 * any legitimate registration.  Per-bucket uint16_t refcount keeps the
 * bit set until the LAST region in that size class drops, mirroring
 * the shared_region_refcount discipline on the address bitmap; the
 * 4352-region worst case (MAX_SHARED_ALLOCS + SHARED_REGIONS_OVERFLOW_
 * TAIL) sits comfortably under UINT16_MAX, so a pathological run that
 * crowds every region into one bucket cannot overflow the counter.
 *
 * size==0 is a no-op for the same reason shared_bitmap_mark() no-ops
 * on size==0: the registering caller treats a zero-byte region as "no
 * region" and floor(log2(0)) is undefined, so suppressing the bump
 * here keeps the bitmaps in lockstep and avoids a spurious bucket-0
 * entry that no matching untrack would ever clear.
 */
#define TRACKED_SIZE_NBUCKETS	64
unsigned long tracked_size_bm;
static uint16_t tracked_size_bucket_count[TRACKED_SIZE_NBUCKETS];

static inline unsigned int tracked_size_bucket(unsigned long len)
{
	return 63u - (unsigned int)__builtin_clzl(len);
}

static void tracked_size_mark(unsigned long len)
{
	unsigned int b;

	if (len == 0)
		return;

	b = tracked_size_bucket(len);
	if (b >= TRACKED_SIZE_NBUCKETS) {
		outputerr("tracked_size_mark: bucket %u out of range for len 0x%lx\n",
			  b, len);
		BUG("tracked_size bucket out of range");
	}
	if (tracked_size_bucket_count[b] == UINT16_MAX) {
		outputerr("tracked_size_mark: bucket %u refcount overflow for len 0x%lx\n",
			  b, len);
		BUG("tracked_size bucket refcount overflow");
	}
	if (tracked_size_bucket_count[b]++ == 0)
		tracked_size_bm |= 1UL << b;
}

static void tracked_size_unmark(unsigned long len)
{
	unsigned int b;

	if (len == 0)
		return;

	b = tracked_size_bucket(len);
	if (b >= TRACKED_SIZE_NBUCKETS) {
		outputerr("tracked_size_unmark: bucket %u out of range for len 0x%lx\n",
			  b, len);
		BUG("tracked_size bucket out of range");
	}
	if (tracked_size_bucket_count[b] == 0) {
		outputerr("tracked_size_unmark: bucket %u refcount underflow for len 0x%lx\n",
			  b, len);
		BUG("tracked_size bucket refcount underflow");
	}
	if (--tracked_size_bucket_count[b] == 0)
		tracked_size_bm &= ~(1UL << b);
}

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
static void guard_pages_derive_span(void *ret, size_t size,
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
static void *guard_pages_alloc(size_t size)
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
static bool guard_scope_covers(bool is_pool)
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

/*
 * Size-bucketed freelist for shared heap recycling.
 *
 * Eight fixed-size buckets cover the common allocation sizes.  A freed slot
 * whose aligned size falls within a bucket is pushed onto that bucket's
 * lock-free stack; the next alloc of the same size pops it instead of
 * burning new bump space.  Allocations larger than 1024 bytes bypass the
 * freelist and use the bump allocator directly (documented below).
 *
 * The freelist link lives in the slot's own first uint32_t.  This is safe
 * because the slot is not live when the link is written: the caller has
 * just handed it back to us, and we zero the rest of the slot before
 * writing the link so that a use-after-free still surfaces as zero-byte
 * reads rather than as a stale link token.
 *
 * CAS ordering.  A naive RELAXED-everywhere scheme is fine on x86-64's
 * strong model but corrupts on weak-memory architectures (arm64, riscv):
 * a popper could observe a head installed by an in-flight push before the
 * push's earlier store to the slot's link word had propagated, and then
 * dereference an uninitialised or stale link.  So:
 *
 *   push: success CAS is RELEASE, failure is RELAXED.  The release
 *   pairs with pop's acquire load below, ordering the slot-link store
 *   (which is a plain non-atomic write inside the CAS loop) before the
 *   head publication that other poppers see.
 *
 *   pop: the initial head load is ACQUIRE, the success CAS is ACQ_REL,
 *   and the failure CAS is ACQUIRE.  Acquire on both the load and the
 *   failure path guarantees the retry re-reads with acquire semantics
 *   before it dereferences the linked slot; ACQ_REL on success makes the
 *   pop safe to sequence with subsequent pushes of the same slot.
 *
 * ABA safety via tagged head.  A naive lock-free stack with a single
 * token head is vulnerable to the classic ABA race: a popper reads
 * old_head=X and next=*X, but before its CAS another thread pops X, pops
 * X.next, and then pushes X back.  The CAS still sees head==X and succeeds,
 * but it installs the stale "next" value, leaving head pointing at a slot
 * that has already been handed back to a caller.  Two callers then think
 * they own the same slot; the resulting double-use corrupts whichever
 * obj struct was layered over the slot and faults later in unrelated
 * code paths far from the buggy free.
 *
 * The mitigation is a 32-bit version counter packed into the high half of
 * the head word.  Each push and pop increments the version; the CAS
 * compares the full 64-bit (version, token) tuple.  The A→B→A sequence
 * above now leaves the head as (X, ver+2) rather than (X, ver), so the
 * racer's CAS fails on the version mismatch and it retries with a fresh
 * load.
 *
 * The packing uses a heap-offset token instead of the old x86-64 48-bit
 * pointer trick: low 32 bits carry (offset+1), high 32 bits carry the
 * version.  Offsets are stable across processes that mmap the shared
 * heap at different base addresses, and the encoding assumes nothing
 * about pointer layout, so the same code compiles and runs correctly on
 * arm64/riscv/s390x/x86-64-5-level.  Token 0 is the empty-list sentinel;
 * offset+1 guarantees offset-0 never encodes to 0.  See the
 * FREELIST_OFF_MASK block below for the exact bit layout.
 *
 * The 32-bit version is effectively unwrappable in practice: a targeted
 * ABA would need 2^32 push/pop pairs interleaved between a victim's
 * load and CAS; at sub-microsecond critical sections and a
 * process-bounded fuzzer this is astronomically improbable.
 */

/*
 * Base pointer of the shared string heap.  Freelist tokens encode an
 * offset+1 into this region; both push and pop translate between tokens
 * and pointers via this base, so it must be visible above the freelist
 * primitives.  The actual mapping is created lazily in
 * shared_str_heap_init() below the freelist code.
 */
static char *shared_str_heap;

/*
 * The head-word packing uses a heap-offset token instead of a raw pointer,
 * which makes it arch-portable: no assumption about pointer widths, no
 * dependency on x86-64's canonical 48-bit userspace VA layout, and no
 * conflict with 52-bit VA arm64 or 5-level-paging x86-64.
 *
 *   low 32 bits  = token = (slot_offset_in_heap + 1)
 *   high 32 bits = version counter (ABA guard)
 *
 * Token 0 is reserved as the empty-list sentinel.  Offsets themselves run
 * from 0 to SHARED_STR_HEAP_SIZE-1, so token 1 unambiguously names the
 * slot at offset 0 and no valid slot ever encodes to 0.  The version tag
 * remains in the high 32 bits and still defeats the classic ABA race in
 * freelist_pop (see the long block comment above).
 *
 * The slot's stored "next" word is the next slot's token, not a raw
 * pointer — the same offset+1 encoding — so the whole invariant (any
 * value written into head or slot link is a valid token) survives across
 * processes that map the shared heap at different base addresses.
 *
 * The bound on the offset+1 token is UINT32_MAX (not 1U<<32 — that shift
 * is a width-of-type UB on a 32-bit int).  SHARED_STR_HEAP_SIZE at the
 * current 1 MiB is well under that; the _Static_assert lives beside the
 * SHARED_STR_HEAP_SIZE define so any future growth trips the compile.
 */
#define FREELIST_OFF_MASK	((uint64_t)0xffffffffULL)
#define FREELIST_VER_SHIFT	32

static const size_t bucket_sizes[NUM_SHM_FREELIST_BUCKETS] = {
	8, 16, 32, 64, 128, 256, 512, 1024
};

/*
 * Return the index of the smallest bucket that fits an allocation of
 * already-pointer-aligned size, or -1 if size exceeds all buckets.
 */
static int freelist_bucket(size_t aligned_size)
{
	unsigned int i;

	for (i = 0; i < NUM_SHM_FREELIST_BUCKETS; i++) {
		if (aligned_size <= bucket_sizes[i])
			return (int)i;
	}
	return -1;
}

/*
 * Pop a slot from the freelist bucket whose head lives at *head.
 * Returns NULL if the freelist is empty; otherwise returns a fully-zeroed
 * slot of slot_size bytes.  ABA-safe via the version tag in the high half
 * of the head — see the block comment above.  The head load and the
 * failing CAS branch both use ACQUIRE so that the slot-link store from
 * the concurrent push that installed this head is visible before we
 * dereference the link.
 */
static void *freelist_pop(uint64_t *head, size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uint32_t token, next_token;
	uint32_t new_ver;
	void *p;

	old_tagged = __atomic_load_n(head, __ATOMIC_ACQUIRE);
	do {
		token = (uint32_t)(old_tagged & FREELIST_OFF_MASK);
		if (token == 0)
			return NULL;
		p = shared_str_heap + (token - 1);
		/* Slot's first uint32_t holds the next slot's token (offset+1),
		 * with no version bits — versions live only in the head. */
		next_token = *(uint32_t *)p;
		new_ver = (uint32_t)(old_tagged >> FREELIST_VER_SHIFT) + 1;
		new_tagged = ((uint64_t)next_token & FREELIST_OFF_MASK) |
			     ((uint64_t)new_ver << FREELIST_VER_SHIFT);
	} while (!__atomic_compare_exchange_n(head, &old_tagged, new_tagged,
					      false,
					      __ATOMIC_ACQ_REL,
					      __ATOMIC_ACQUIRE));

	memset(p, 0, slot_size);
	return p;
}

/*
 * Push a slot onto the freelist bucket whose head lives at *head.
 * The entire slot (slot_size bytes) is zeroed first so that a use-after-
 * free reads as zero rather than stale data; then the next-slot token is
 * written into the slot's first uint32_t before the CAS.  The version tag
 * in the head is incremented on every successful CAS to keep poppers safe
 * from ABA — see the block comment above.  The success CAS uses RELEASE
 * so poppers that ACQUIRE-load the resulting head see the slot-link store
 * we made just above.
 */
static void freelist_push(uint64_t *head, void *p, size_t slot_size)
{
	uint64_t old_tagged, new_tagged;
	uint32_t my_token, new_ver;

	memset(p, 0, slot_size);
	my_token = (uint32_t)((char *)p - shared_str_heap) + 1;
	old_tagged = __atomic_load_n(head, __ATOMIC_RELAXED);
	do {
		/* Store only the token half of the previous head into our
		 * slot — the version stays in the head word. */
		*(uint32_t *)p = (uint32_t)(old_tagged & FREELIST_OFF_MASK);
		new_ver = (uint32_t)(old_tagged >> FREELIST_VER_SHIFT) + 1;
		new_tagged = ((uint64_t)my_token & FREELIST_OFF_MASK) |
			     ((uint64_t)new_ver << FREELIST_VER_SHIFT);
	} while (!__atomic_compare_exchange_n(head, &old_tagged, new_tagged,
					      false,
					      __ATOMIC_RELEASE,
					      __ATOMIC_RELAXED));
}

/*
 * Shared string heap — backing store for the string PAYLOADS of
 * string-shaped fields (filenames, label strings, fixed-size attr
 * buffers).  The owning obj struct itself comes from alloc_object()/
 * zmalloc_tracked and lives on the private per-process heap; only the
 * variable-length payload it points at is carved from this shared slab.
 *
 * The payload must be MAP_SHARED-before-fork: any obj struct reachable
 * from shm->global_objects[] must point only at memory that other
 * processes can also reach, and the only way to satisfy that for
 * payloads allocated after fork (the regen path) is to carve out of a
 * region that was already mapped before any child forked.
 *
 * Why a dedicated slab for payloads:
 *
 *   A single shared region sized only for variable-length string
 *   payloads keeps its failure mode independent and self-describing:
 *   an exhaustion message reads as "out of string slots" and nothing
 *   else.  Payloads are variable-length and dominated by short labels,
 *   so the pool can stay small.
 *
 * Capacity (1 MiB):
 *
 *   The string-bearing OBJ_GLOBAL providers (file/testfile, perf,
 *   memfd) hold short payloads — file paths typically under ~100 B,
 *   memfd labels under ~32 B, perf_event_attr buffers ~120 B (kernel
 *   caps the attr at PAGE_SIZE but trinity only memcpy's a struct's
 *   worth back into the obj for replay/dump).  At ~64 B average that
 *   is ~16k entries; at ~120 B per perf entry it is ~8.7k.  Slots up
 *   to 1024 B are recycled through the size-bucketed freelists on free,
 *   so steady-state occupancy tracks the live working set rather than
 *   total allocation volume.  Only above-bucket frees bump-and-leak;
 *   the 1 MiB ceiling is headroom for those.
 *
 * Why two entry points (alloc_shared_str + alloc_shared_strdup):
 *
 *   The eventual callers split cleanly into two shapes:
 *
 *     - strdup-style:  init_*_fds() and the .open regen hooks have
 *       a NUL-terminated source string (filename, label) and want a
 *       pointer to a stable shm copy of it.  alloc_shared_strdup()
 *       collapses the strlen+alloc+strcpy sequence at the call site.
 *
 *     - empty-buffer:  perf's open_perf_fd() has a fixed-size attr
 *       struct and just wants raw zeroed bytes to memcpy into.
 *       alloc_shared_str(sizeof(struct perf_event_attr)) hands back
 *       exactly that, with no NUL-termination contract.
 *
 *   Both share one heap and one free; the strdup variant is a thin
 *   wrapper around the primitive, not a separate allocator.
 *
 * Free strategy:
 *
 *   Poison the slot to zeros so a use-after-free surfaces as a "" /
 *   NUL-byte read rather than a live-looking string, then recycle via
 *   the size-bucketed freelist (see freelist_push/pop above).  Callers
 *   pass the original
 *   allocation size; for strdup-style strings that is strlen(p)+1 at
 *   free time, which is correct for a still-NUL-terminated string and
 *   harmless overshoot if it isn't (the buffer was zero-initialised).
 *   Slots too large for any freelist bucket are poisoned and leaked.
 */
/*
 * 1 MiB.  Slots up to 1024 B are returned to the size-bucketed
 * freelists on free, so steady-state occupancy tracks the live
 * working set under OBJ_LOCAL churn (post_*_fd callbacks plus
 * per-child fanout).  Above-bucket frees bump-and-leak — they lose a
 * slot apiece — and the 1 MiB ceiling sizes the headroom that path
 * needs over a sustained fuzz run.
 */
#define SHARED_STR_HEAP_SIZE (1U * 1024U * 1024U)

/*
 * Freelist tokens are (offset+1) and must fit in the low 32 bits of the
 * head word; offset 0 is legal, so the token can be up to
 * SHARED_STR_HEAP_SIZE.  Bounding at UINT32_MAX (not 1U << 32 — that
 * shift is a width-of-type UB) keeps the encoding lossless for any
 * future heap growth.
 */
_Static_assert(SHARED_STR_HEAP_SIZE <= UINT32_MAX,
	       "shared string heap offset+1 must fit in uint32_t");

static size_t shared_str_heap_capacity;

static void shared_str_heap_init(void)
{
	/* Same pre-fork-mapping requirement as the obj heap: the first
	 * caller must run in the parent before any child forks, which
	 * holds for all current callers (init_*_fds via open_fds()
	 * before fork_children()).  Assert it so a future child-context
	 * caller cannot silently map a private heap behind the shared
	 * cursor, which would dangle string pointers across processes. */
	if (getpid() != mainpid) {
		outputerr("alloc_shared_str: heap init from child context "
			  "(pid %d, parent %d) -- would dangle shm pointers\n",
			  getpid(), mainpid);
		abort();
	}
	shared_str_heap_capacity = SHARED_STR_HEAP_SIZE;
	shared_str_heap = alloc_shared_pool(shared_str_heap_capacity);
}

void * alloc_shared_str(size_t size)
{
	size_t old_used, new_used;
	void *p;
	int bucket;

	if (size == 0)
		return NULL;

	if (shared_str_heap == NULL)
		shared_str_heap_init();

	/* Round up so each allocation starts pointer-aligned.  The
	 * primitive is generic — strings don't need it, but the empty-
	 * buffer callers (perf_event_attr) do, and one rule keeps the
	 * accounting simple. */
	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	/* Try the freelist before touching the bump cursor. */
	bucket = freelist_bucket(size);
	if (bucket >= 0) {
		p = freelist_pop(&shm->shared_str_freelist[bucket],
				 bucket_sizes[bucket]);
		if (p != NULL)
			return p;
		/* Round bump to bucket size so the first free of a bump
		 * slot doesn't overrun the next slot via freelist_push's
		 * bucket-size memset. */
		size = bucket_sizes[bucket];
	}

	/* Lock-free bump via CAS on the shm-resident cursor.  RELAXED
	 * is sufficient because the caller publishes the obj (and therefore the string pointer)
	 * to consumers via add_object()'s RELEASE store on
	 * num_entries. */
	old_used = __atomic_load_n(&shm->shared_str_heap_used,
				   __ATOMIC_RELAXED);
	do {
		new_used = old_used + size;
		if (new_used > shared_str_heap_capacity) {
			outputerr("alloc_shared_str: heap exhausted "
				  "(cap %zu, used %zu, req %zu)\n",
				  shared_str_heap_capacity, old_used,
				  size);
			return NULL;
		}
	} while (!__atomic_compare_exchange_n(&shm->shared_str_heap_used,
					      &old_used, new_used,
					      false,
					      __ATOMIC_RELAXED,
					      __ATOMIC_RELAXED));

	p = shared_str_heap + old_used;
	memset(p, 0, size);
	return p;
}

char * alloc_shared_strdup(const char *src)
{
	size_t len;
	char *dst;

	if (src == NULL)
		return NULL;

	len = strlen(src) + 1;
	dst = alloc_shared_str(len);
	if (dst == NULL)
		return NULL;

	memcpy(dst, src, len);
	return dst;
}

void free_shared_str(void *p, size_t size)
{
	int bucket;

	if (p == NULL || size == 0)
		return;

	size = (size + sizeof(void *) - 1) & ~(sizeof(void *) - 1);

	bucket = freelist_bucket(size);
	if (bucket >= 0) {
		freelist_push(&shm->shared_str_freelist[bucket], p,
			      bucket_sizes[bucket]);
		return;
	}

	/* Size above all buckets — poison and leak (bump-and-leak fallback). */
	memset(p, 0, size);
}

/*
 * Self-check: confirm range_overlaps_shared()'s bitmap accelerator
 * actually rejects the first registered region.  Catches construction
 * regressions (a future refactor that forgets to call
 * shared_bitmap_mark() at registration would otherwise fail open and
 * silently let the fuzzer clobber trinity's own shared state).  Runs
 * once -- the bitmap only grows with new registrations, so a single
 * positive assert is sufficient to prove the wiring works. */
void shared_bitmap_self_check(void)
{
	static bool checked;
	unsigned long base, bit;

	if (checked || nr_shared_regions == 0)
		return;
	checked = true;

	base = shared_regions[0].addr;
	/*
	 * The bitmap only tracks addresses inside its span; above-span
	 * registrations are recorded in shared_regions[] alone and the
	 * query path falls back to a linear scan for them.  Asserting on
	 * such an entry would read past the bitmap.
	 */
	if (base < SHARED_BITMAP_VA_SPAN) {
		bit = base >> SHARED_BITMAP_GRANULARITY_LOG2;
		if (!shared_bitmap_test(bit)) {
			outputerr("range_overlaps_shared bitmap missing first region "
				  "@ 0x%lx (bit %lu)\n", base, bit);
			BUG("shared region bitmap inconsistent");
		}
	}

	/*
	 * Companion size-bucket bitmap should also reflect the first
	 * registered region: any region with non-zero size lands in some
	 * bucket, so tracked_size_bm cannot be empty here.  Catches a
	 * future refactor that wires shared_bitmap_mark() but forgets the
	 * parallel tracked_size_mark() call -- silent under-protection of
	 * the size short-circuit (always-true skip on an empty bitmap)
	 * would defeat the bypass counter on every call.
	 */
	if (shared_regions[0].size != 0 && tracked_size_bm == 0) {
		outputerr("tracked_size_bm empty despite first region size 0x%lx\n",
			  shared_regions[0].size);
		BUG("tracked_size bitmap inconsistent");
	}
}
