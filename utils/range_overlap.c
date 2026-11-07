#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include "child.h"
#include "debug.h"
#include "params.h"
#include "pids.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"

/* Tunable: how often range_overlaps_shared() emits a -v summary line.
 * Lower = noisier, higher = blunter. */
#define RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL 10000

/* Sibling tunable for the size-bucket bitmap short-circuit path.
 * Same cadence as the rejects line above so the two -v summaries
 * stay in lockstep when both fire on the same child. */
#define RANGE_OVERLAPS_SHARED_BM_SKIP_REPORT_INTERVAL 10000

/*
 * Exact byte-range overlap confirmation after a bitmap hit.  The
 * bitmap rounds tracked regions up to 2 MiB chunks, so a hit means
 * "some tracked region lives in a chunk that touches the query" --
 * not that the query and the region share a byte.  Walking the two
 * region arrays here resolves the false positives in which a valid,
 * disjoint mm-syscall range shares a 2 MiB chunk with a tracked
 * allocation; the bitmap previously rejected those unconditionally,
 * losing real munmap / mremap / madvise / mprotect / mbind coverage on
 * hosts where allocations cluster.
 *
 * Semantics match the pre-bitmap byte-precise test:
 *   - a non-empty range [addr, end) overlaps [rstart, rend) iff
 *     addr < rend && rstart < end (standard interval overlap);
 *   - an empty (len == 0) range matches iff @addr is strictly inside
 *     a region (rstart <= addr < rend), which is the only empty-range
 *     case the original test accepted.
 *
 * Zero-size tracked regions never overlap anything, matching the
 * alloc_shared() / track_shared_region() callers that treat size==0
 * as "no region" (and matching shared_bitmap_mark()'s no-op on size 0).
 *
 * Returning false here only removes false-positive rejects; it never
 * accepts a query that truly overlaps a tracked region, so the safety
 * invariant the callers rely on (no fuzzed mm-syscall clobbers a
 * trinity-owned shared mapping) is preserved.
 */
static bool shared_regions_exact_overlap(unsigned long addr,
					 unsigned long len,
					 unsigned long end)
{
	const struct shared_region_entry *r;
	unsigned int i;

	for_each_shared_region(i, r) {
		unsigned long rstart = r->addr;
		unsigned long rsize = r->size;
		unsigned long rend;

		if (rsize == 0)
			continue;
		rend = rstart + rsize;

		if (len == 0) {
			if (addr >= rstart && addr < rend)
				return true;
		} else {
			if (addr < rend && rstart < end)
				return true;
		}
	}

	return false;
}

/* Last syscall to trip a range_overlaps_shared() reject.  Last-write-wins;
 * a coarse hint for which sanitiser is doing the most work, not a precise
 * audit trail.  Process-local statics: each child has its own copy, the
 * writer and the reader (the periodic -v summary below) live in the same
 * single-threaded child, so plain accesses suffice.  Torn reads are
 * acceptable for a diagnostic anyway. */
static unsigned int last_reject_syscall_nr;
static unsigned char last_reject_do32bit;
static unsigned char last_reject_have_syscall;

bool range_overlaps_shared(unsigned long addr, unsigned long len)
{
	unsigned long end, check_end, first, last;
	bool overlap = false;
	unsigned long n;
	struct childdata *child;

	/* Treat wrapped ranges as overlapping so callers reject them. */
	if (len != 0 && addr > ULONG_MAX - len)
		return true;

	end = addr + len;

	/*
	 * Size-bucket bitmap short-circuit: when no tracked region of any
	 * size class exists, the address-keyed shared_region_bitmap is
	 * also empty by construction, and the word-scan below would walk
	 * SHARED_BITMAP_NWORDS words to confirm.  One load on
	 * tracked_size_bm proves the same negative in O(1).  This is the
	 * useful empty-fleet / pre-registration / fully-untracked state;
	 * it also covers the bypass condition from the spec ("len exceeds
	 * every set bit's bucket bound") vacuously when no bits are set.
	 *
	 * Per-process rate-limited counter feeds the -v summary below.
	 * Each child has its own static via fork CoW, mirroring the
	 * cadence of the rejects line at the tail of this function.
	 */
	if (tracked_size_bm == 0) {
		static unsigned long local_skip;
		unsigned long s;

		s = ++local_skip;
		if (verbosity > 1 &&
		    (s % RANGE_OVERLAPS_SHARED_BM_SKIP_REPORT_INTERVAL) == 0)
			output(1, "range_overlaps_shared_bm_skip: %lu cumulative bitmap-empty short-circuits\n",
				s);
		return false;
	}

	/* Bitmap accelerator used as a fast NEGATIVE prefilter:
	 * O(ceil(len/2MB)+1) bit reads to rule out the common case where
	 * no tracked region lives in any 2 MiB chunk the query touches.
	 * The bitmap only covers [0, SHARED_BITMAP_VA_SPAN); queries that
	 * start above the span (or straddle it) cannot use the bitmap as
	 * an authoritative negative -- shared_bitmap_mark() no-ops for
	 * those addresses, and the authoritative shared_regions[] linear
	 * scan below answers the membership question for them.  A
	 * zero-length probe collapses to a single bit read on the chunk
	 * containing addr.
	 *
	 * A bitmap HIT is only a candidate: it means at least one
	 * tracked region lives in a chunk that touches the query, but
	 * chunk rounding turns disjoint ranges in the same chunk into
	 * false positives.  The exact byte-range walk below confirms the
	 * hit (or clears it) before we reject. */
	if (addr < SHARED_BITMAP_VA_SPAN) {
		check_end = end;
		if (check_end > SHARED_BITMAP_VA_SPAN)
			check_end = SHARED_BITMAP_VA_SPAN;

		first = addr >> SHARED_BITMAP_GRANULARITY_LOG2;
		if (check_end > addr)
			last = (check_end - 1) >> SHARED_BITMAP_GRANULARITY_LOG2;
		else
			last = first;

		/* Word-at-a-time scan over shared_region_bitmap[]:
		 * mask the partial first/last words, then sweep any
		 * middle words and skip the zero-word common case in a
		 * single load.  A mostly-empty bitmap with a multi-MiB
		 * query length now costs one load per 64 chunks (128 MiB
		 * of VA), not one per chunk. */
		{
			unsigned long first_word = first / SHARED_BITMAP_BITS_PER_WORD;
			unsigned long last_word  = last  / SHARED_BITMAP_BITS_PER_WORD;
			unsigned long first_off  = first % SHARED_BITMAP_BITS_PER_WORD;
			unsigned long last_off   = last  % SHARED_BITMAP_BITS_PER_WORD;
			unsigned long w;

			if (first_word == last_word) {
				unsigned long width = last_off - first_off + 1;
				unsigned long mask  = (width == SHARED_BITMAP_BITS_PER_WORD)
					? ~0UL
					: (((1UL << width) - 1UL) << first_off);

				if (shared_region_bitmap[first_word] & mask)
					overlap = true;
			} else {
				unsigned long head_mask = ~0UL << first_off;

				if (shared_region_bitmap[first_word] & head_mask) {
					overlap = true;
				} else {
					for (w = first_word + 1; w < last_word; w++) {
						if (shared_region_bitmap[w]) {
							overlap = true;
							break;
						}
					}
					if (!overlap) {
						unsigned long tail_width = last_off + 1;
						unsigned long tail_mask  = (tail_width == SHARED_BITMAP_BITS_PER_WORD)
							? ~0UL
							: ((1UL << tail_width) - 1UL);

						if (shared_region_bitmap[last_word] & tail_mask)
							overlap = true;
					}
				}
			}
		}
	}

	/* Above-span / span-straddling queries cannot trust a bitmap
	 * negative: shared_bitmap_mark() no-ops for those addresses, so
	 * a registered region up there leaves no bitmap trace.  Force
	 * the candidate flag so the shared_regions[] linear scan below
	 * answers the membership question authoritatively. */
	if (addr >= SHARED_BITMAP_VA_SPAN ||
	    (len != 0 && len > SHARED_BITMAP_VA_SPAN - addr))
		overlap = true;

	if (!overlap)
		return false;

	/* Bitmap hit: confirm there is real byte-range overlap before
	 * rejecting.  This is the rarer path (bitmap-clear cases already
	 * returned above), so paying an O(N) walk here is cheap on the
	 * common fast path and only fires when the query genuinely
	 * shares a 2 MiB chunk with a tracked region. */
	if (!shared_regions_exact_overlap(addr, len, end))
		return false;

	child = this_child();
	if (child != NULL && child->stats_ring != NULL) {
		unsigned int nr = child->syscall.nr;
		bool do32 = child->syscall.do32bit;

		stats_ring_enqueue(child->stats_ring,
				   STATS_FIELD_RANGE_OVERLAPS_SHARED_REJECTS,
				   0, 1);
		if (nr < MAX_NR_SYSCALL) {
			enum stats_field f = do32
				? STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_32
				: STATS_FIELD_RANGE_REJECTS_PER_SYSCALL_64;
			stats_ring_enqueue(child->stats_ring, f,
					   (uint16_t)nr, 1);
		}

		last_reject_syscall_nr = nr;
		last_reject_do32bit = do32 ? 1 : 0;
		last_reject_have_syscall = 1;
	} else {
		/* Parent / pre-fork context: bump the aggregate directly. */
		parent_stats.range_overlaps_shared_rejects++;
	}

	/* Per-process monotonic counter feeding the verbose rate-limited
	 * log below.  The canonical aggregate now lives in parent-private
	 * memory and is not directly visible from child context, so the
	 * "fleet-wide every Nth reject" cadence the original counter
	 * provided cannot be recovered cheaply.  Each child rate-limits
	 * its own log lines independently; the parent does the same.
	 * Verbosity-gated, informational only. */
	{
		static unsigned long local_n;

		n = ++local_n;
	}

	if (verbosity > 1 &&
	    (n % RANGE_OVERLAPS_SHARED_REJECT_REPORT_INTERVAL) == 0) {
		const char *sname = "?";
		unsigned int snr;
		unsigned char s32;

		if (last_reject_have_syscall) {
			snr = last_reject_syscall_nr;
			s32 = last_reject_do32bit;
			sname = print_syscall_name(snr, s32 != 0);
		}

		output(1, "range_overlaps_shared: %lu cumulative rejects "
			"(latest syscall=%s addr=0x%lx len=%lu)\n",
			n, sname, addr, len);
	}
	return true;
}

/*
 * Precise containment check: is [addr, addr+len) fully inside at least
 * one entry of shared_regions[]?  Used by get_writable_address() to
 * confirm a freshly-picked pool address still resolves to a tracked
 * mapping before handing it back to a sanitiser.
 *
 * Distinct from range_overlaps_shared() in three ways the caller
 * relies on:
 *   1. Polarity is "fully inside", not "overlaps".  A scribbled slot
 *      can hold a value that happens to abut a tracked region without
 *      being inside it; over-acceptance there would defeat the guard.
 *   2. Walks shared_regions[] linearly.  The bitmap accelerator that
 *      backs range_overlaps_shared() rounds to 2 MiB chunks, which is
 *      the SAFETY direction for a reject-shaped sanitiser but the
 *      WRONG direction here -- a 2 MiB chunk that contains some
 *      tracked region would falsely accept addresses elsewhere in the
 *      same chunk.
 *   3. Does not bump range_overlaps_shared_rejects.  This is a
 *      validation lookup, not a sanitiser reject; folding it into the
 *      reject counter would lie to the operator about how often the
 *      mm-syscall guards are firing.
 *
 * Empty ranges (len == 0) match if @addr lies strictly inside any
 * region; the caller controls len so this is the consistent shape.
 * Wrapped ranges return false (no real allocation can wrap user VA).
 */
bool range_in_tracked_shared(unsigned long addr, unsigned long len)
{
	const struct shared_region_entry *r;
	unsigned long end;
	unsigned int i;

	if (len != 0 && addr > ULONG_MAX - len)
		return false;

	end = addr + len;

	/* The overflow tail counts too: a region parked there is no less
	 * tracked from the caller's perspective, and a false negative
	 * would let get_writable_address() hand back a pool slot that no
	 * longer resolves to a tracked mapping. */
	for_each_shared_region(i, r) {
		unsigned long rstart = r->addr;
		unsigned long rend = rstart + r->size;

		if (addr >= rstart && end <= rend)
			return true;
	}
	return false;
}

/*
 * Return the bytes remaining from @addr to the end of the tracked
 * shared region that contains it, or 0 if @addr does not fall inside
 * any tracked region.  Callers use the result as the writable extent
 * available at @addr -- a kernel-WRITES-buffer caller that picks a
 * length <= this value cannot make the kernel scribble past the
 * region into the abutting page.
 *
 * The overflow tail is walked too, so a region that arrived after
 * shared_regions[] was full is no less lookup-able than one in the
 * main array.  A zero return is the documented "no companion size
 * resolvable" signal and the caller is expected to fall back to the
 * size-agnostic get_len() rather than guessing.
 */
unsigned long shared_region_size_for(unsigned long addr)
{
	const struct shared_region_entry *r;
	unsigned int i;

	/* range_overlaps_shared()'s bitmap negative, for one byte: a clear
	 * bit for addr's 2 MiB chunk proves no tracked region holds addr,
	 * so a miss (a mapping-pool base, a sentinel) costs one load, not a
	 * walk of every region.  Above the span the walk answers alone. */
	if (addr < SHARED_BITMAP_VA_SPAN) {
		unsigned long bit = addr >> SHARED_BITMAP_GRANULARITY_LOG2;

		if (!(shared_region_bitmap[bit / SHARED_BITMAP_BITS_PER_WORD] &
		      (1UL << (bit % SHARED_BITMAP_BITS_PER_WORD))))
			return 0;
	}

	for_each_shared_region(i, r) {
		unsigned long rstart = r->addr;
		unsigned long rsize = r->size;

		if (rsize == 0)
			continue;
		if (addr >= rstart && addr < rstart + rsize)
			return rsize - (addr - rstart);
	}
	return 0;
}
