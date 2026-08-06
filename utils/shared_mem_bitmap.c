/*
 * Bitmap + size-bucket accelerators for range_overlaps_shared().
 *
 * shared_region_bitmap[]: one bit per 2 MiB chunk of user VA; set when
 * at least one tracked shared region touches the chunk.  Turns the hot
 * O(N) linear scan into one or two word loads for the common query.
 *
 * tracked_size_bm / tracked_size_bucket_count[]: 64-bucket log2 bitmap
 * encoding whether any tracked region exists in each size class; allows
 * range_overlaps_shared() to short-circuit early when the pool is empty.
 *
 * Both bitmaps use per-chunk uint16_t refcounts so that a bit stays set
 * until the LAST tracked region in that chunk / bucket is removed.
 *
 * shared_bitmap_self_check() asserts the positive-path wiring of both
 * bitmaps at startup.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include "debug.h"
#include "trinity.h"
#include "utils-internal.h"
#include "shared_mem-internal.h"

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
void shared_bitmap_mark(unsigned long addr, unsigned long size)
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
void shared_bitmap_unmark(unsigned long addr, unsigned long size)
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

void tracked_size_mark(unsigned long len)
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

void tracked_size_unmark(unsigned long len)
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
