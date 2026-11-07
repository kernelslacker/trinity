#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "child.h"
#include "debug.h"
#include "shm.h"
#include "stats.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"
#include "utils-internal.h"

/*
 * Cached extent of the brk()-managed glibc arena, captured once at
 * init time from /proc/self/maps.  COW-shared into every forked
 * child, so a single pre-fork parse seeds the whole fleet.  heap_start
 * is stable for the lifetime of the process (the brk base doesn't
 * move), but heap_end is only a snapshot -- a child that extends brk
 * post-fork (millions of iterations of getline in /proc parsers,
 * libasan shadow growth, heavy zmalloc traffic) sails past it, so
 * consumers also consult sbrk(0) for the current break.  glibc's
 * sbrk(0) answers from its own cached break (__curbrk) without a
 * syscall once that is set, so every check asks afresh.  Zero start
 * means we never found a [heap] line; in that case is_in_glibc_heap()
 * falls back to "always true" so we don't reject legitimate frees on
 * platforms or builds where glibc has chosen an mmap-only allocation
 * strategy and the brk arena is empty.
 */
static unsigned long heap_start;
static unsigned long heap_end;

/*
 * Cached extents of non-brk allocator arenas, captured alongside the
 * [heap] line at heap_bounds_init() time.  glibc's mmap'd arenas, the
 * sanitiser-runtime allocator reservations (libasan primary/secondary
 * at 0x511000000000+, the shadow region, ...), scudo / jemalloc /
 * tcmalloc -- every well-behaved allocator labels its anonymous
 * mappings via prctl(PR_SET_VMA_ANON_NAME), which shows up in
 * /proc/self/maps as "[anon:NAME]" after the inode column.  Trinity
 * itself does not label any of its scratch mappings, so an
 * "[anon:*]" tag in the pre-fork snapshot identifies a region whose
 * contents must not be overwritten by a fuzzed kernel-write
 * argument (the alternative is a write into glibc / libasan chunk
 * metadata, surfacing later as an arena-corruption abort or an
 * ASAN bad-free).
 *
 * 16 entries comfortably covers the regions seen on a libasan-built
 * trinity under glibc 2.39 (one [heap], two glibc mmap arenas, four
 * libasan shadow / allocator regions); an overflow logs once and
 * leaves the trailing regions unprotected -- the wrong direction for
 * safety, so the cap exists to be hit and bumped if a future libsan
 * layout adds more regions.
 */
#define MAX_EXTRA_HEAP_REGIONS	16
struct heap_region {
	unsigned long start;
	unsigned long end;
};
static struct heap_region extra_heap_regions[MAX_EXTRA_HEAP_REGIONS];
static unsigned int nr_extra_heap_regions;

/*
 * Bounding box (min start, max end) over extra_heap_regions[],
 * recomputed atomically in heap_bounds_init() alongside the slot
 * snapshot.  Used by range_overlaps_libc_heap() as a coarse
 * "looks heap-shaped" signal: a query that falls inside the bbox
 * but matches no specific slot is the canonical staleness shape --
 * a post-init secondary mmap (large malloc one-VMA-per-alloc) that
 * landed between the captured slots and is therefore not in the
 * snapshot.  Bbox is empty (end <= start) when no extras have been
 * captured, in which case the predicate degenerates to "never".
 */
static unsigned long extra_heap_regions_bbox_start;
static unsigned long extra_heap_regions_bbox_end;

/*
 * Threshold of "looks heap-shaped but missed all slots" observations
 * before range_overlaps_libc_heap() pays for one /proc/self/maps
 * re-parse and rebuilds extra_heap_regions[].  Set high enough that
 * the common cache-hit path stays at its existing cost (a few
 * compares), low enough that a real post-init secondary mmap is
 * picked up within a small bounded number of misses.  Per-child
 * static -- a child whose own allocator just spawned a new arena
 * refreshes once and then stops missing.
 */
#define HEAP_OUTSIDE_CACHE_REFRESH_THRESHOLD 64

/*
 * Parse a /proc/self/maps line just enough to extract the
 * [start, end), the perms field, and the trailing path/label.  Returns
 * true on success.  The label pointer (which may be NULL or point at
 * the empty string) is written into *label_out; it points into @line,
 * which the caller owns.
 *
 * A line looks like:
 *   55a1b3c00000-55a1b3c21000 rw-p 00000000 00:00 0   [heap]
 *   7f2c1b400000-7f2c1b421000 rw-p 00000000 00:00 0   [anon:libc_malloc]
 *   55a1b3a00000-55a1b3a21000 rw-p 00000000 00:00 0
 * i.e. start-end perms offset major:minor inode optional-label.
 */
static bool parse_maps_line(char *line, unsigned long *start_out,
			    unsigned long *end_out, char perms_out[5],
			    const char **label_out)
{
	unsigned long start, end;
	char perms[8];
	int label_off = -1;
	const char *label;
	char *nl;

	nl = strchr(line, '\n');
	if (nl != NULL)
		*nl = '\0';

	if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*u %n",
		   &start, &end, perms, &label_off) < 3)
		return false;
	if (end <= start)
		return false;

	if (label_off < 0 || (size_t) label_off > strlen(line))
		label = "";
	else
		label = line + label_off;

	*start_out = start;
	*end_out = end;
	memcpy(perms_out, perms, 4);
	perms_out[4] = '\0';
	*label_out = label;
	return true;
}

/*
 * Parse /proc/self/maps and stash the brk arena plus every labeled
 * non-brk allocator region.  Called once pre-fork by the parent and
 * once per child from init_child() (after all the post-fork startup
 * mmap traffic has settled) so glibc mmap arenas that the child's
 * own allocator storm spawned after fork are captured -- without the
 * per-child re-parse, those arenas live outside the inherited
 * snapshot and a wild pointer landing in one slips past the overlap
 * gate, letting the kernel scribble glibc chunk metadata and
 * surfacing later as an arena-corruption abort with no proximate
 * reproducer.
 *
 * The parse is committed atomically into module state on success.
 * A failed open (vanishingly rare for /proc/self/maps on our own
 * pid) preserves whatever snapshot was previously in place: the
 * child's COW-inherited parent snapshot stays valid as a fallback
 * rather than collapsing to an empty validator that lets every
 * address through.
 *
 * If the [heap] line is missing (rare: glibc tuned to
 * MALLOC_MMAP_THRESHOLD_=0 or the binary somehow hasn't grown brk
 * yet), heap_start stays 0 and is_in_glibc_heap() falls back to
 * "always true" -- we'd rather permit a marginal free than reject
 * every malloc result on a misconfigured host.
 */
void heap_bounds_init(void)
{
	FILE *f;
	char line[512];
	unsigned long new_heap_start = 0, new_heap_end = 0;
	struct heap_region new_regions[MAX_EXTRA_HEAP_REGIONS];
	unsigned int new_nr = 0;

	f = fopen("/proc/self/maps", "r");
	if (f == NULL) {
		outputerr("heap_bounds_init: open /proc/self/maps failed: %s\n",
			  strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long start, end;
		char perms[5];
		const char *label;

		if (!parse_maps_line(line, &start, &end, perms, &label))
			continue;

		/*
		 * Only writable private mappings can hold allocator
		 * metadata that the kernel scribbling would corrupt.
		 * Read-only and shared mappings either can't be written
		 * by the kernel (r-- / r-x) or are trinity-controlled
		 * (MAP_SHARED via alloc_shared / track_shared_region,
		 * handled separately by range_overlaps_shared()).
		 */
		if (perms[1] != 'w' || perms[3] != 'p')
			continue;

		if (strncmp(label, "[heap]", 6) == 0 &&
		    (label[6] == '\0' || label[6] == ' ')) {
			new_heap_start = start;
			new_heap_end = end;
			continue;
		}

		/*
		 * "[anon:NAME]" labels come from
		 * prctl(PR_SET_VMA_ANON_NAME) -- glibc malloc tags its
		 * mmap'd arenas, libasan tags its primary / secondary
		 * allocator and shadow reservations, similarly for
		 * scudo / jemalloc / tcmalloc.  Trinity never labels
		 * its own anonymous mappings, so any "[anon:*]" line
		 * in the snapshot belongs to a non-trinity allocator.
		 * Trinity's BSS, stack, vdso, vvar, file-backed
		 * mappings and unlabeled scratch regions are filtered
		 * out by the perms / label tests above.
		 */
		if (strncmp(label, "[anon:", 6) != 0)
			continue;

		if (new_nr >= MAX_EXTRA_HEAP_REGIONS) {
			static bool warned;

			/*
			 * The outputerr fires once per process so the log
			 * doesn't blow up when many regions overflow; the
			 * counter advances on every dropped region so the
			 * post-mortem reader sees the deficit size rather
			 * than just "deficit existed".
			 */
			__atomic_add_fetch(
				&shm->stats.diag.heap_extra_regions_overflow, 1,
				__ATOMIC_RELAXED);

			if (!warned) {
				warned = true;
				outputerr("heap_bounds_init: "
					"MAX_EXTRA_HEAP_REGIONS (%d) reached "
					"-- '%s' and any subsequent allocator "
					"regions are unprotected; raise the "
					"cap\n",
					MAX_EXTRA_HEAP_REGIONS, label);
			}
			continue;
		}

		new_regions[new_nr].start = start;
		new_regions[new_nr].end = end;
		new_nr++;
	}

	fclose(f);

	/*
	 * Commit the freshly-parsed snapshot in one shot.  On the
	 * child-side refresh path this rewrites the COW-inherited
	 * parent snapshot in the child's now-private BSS pages; the
	 * parent's copy and any sibling's copy are unaffected.
	 */
	heap_start = new_heap_start;
	heap_end = new_heap_end;
	memcpy(extra_heap_regions, new_regions,
	       new_nr * sizeof(new_regions[0]));
	nr_extra_heap_regions = new_nr;

	/*
	 * Recompute the extras bbox alongside the slot snapshot.  An
	 * empty snapshot leaves the bbox closed (start=end=0) so the
	 * "looks heap-shaped" predicate in range_overlaps_libc_heap()
	 * cannot fire spuriously when extras are not yet populated.
	 */
	if (new_nr > 0) {
		unsigned long bbox_lo = new_regions[0].start;
		unsigned long bbox_hi = new_regions[0].end;
		unsigned int i;

		for (i = 1; i < new_nr; i++) {
			if (new_regions[i].start < bbox_lo)
				bbox_lo = new_regions[i].start;
			if (new_regions[i].end > bbox_hi)
				bbox_hi = new_regions[i].end;
		}
		extra_heap_regions_bbox_start = bbox_lo;
		extra_heap_regions_bbox_end = bbox_hi;
	} else {
		extra_heap_regions_bbox_start = 0;
		extra_heap_regions_bbox_end = 0;
	}
}

/*
 * Bounds check: is @p inside any captured glibc-managed allocator
 * region?  Accepts the brk arena AND the labeled non-brk
 * allocator regions stashed by heap_bounds_init() (glibc mmap arenas,
 * libasan primary/secondary/shadow, scudo / jemalloc / tcmalloc
 * tagged regions -- see extra_heap_regions[]).  Returns true if no
 * allocator extent is known at all (init found neither a [heap] line
 * nor any [anon:NAME] regions) so the caller treats the validator as
 * permissive in that case.
 *
 * Checking the brk arena alone would reject legitimate frees of two
 * important pointer classes:
 *   - allocations above MMAP_THRESHOLD (default 128 KiB), which glibc
 *     services from mmap'd arenas rather than brk, and
 *   - every allocation under ASAN, whose libasan-runtime allocator
 *     hands back chunks from its shadow-mapped pools outside brk.
 *
 * Backstop for the bad-free class where a sibling stomp scribbles a
 * snapshot/arg slot with a value that defeats both the pointer-shape
 * heuristic (looks_like_corrupted_ptr) and -- in the worst case --
 * coincidentally matches a tracked malloc result still resident in
 * the alloc-track ring.  An attacker-controlled or wildly-stomped
 * value that lands outside every allocator region (stack, shared
 * region, mmap'd library, executable mapping) is rejected here even
 * if the upstream guards let it through.
 */
bool is_in_glibc_heap(const void *p)
{
	unsigned long v = (unsigned long) p;
	unsigned long end, cur;
	unsigned int i;

	if (heap_start == 0 && nr_extra_heap_regions == 0)
		return true;

	if (heap_start != 0) {
		/*
		 * heap_end is a pre-fork snapshot.  A long-running child
		 * can extend brk past it, so sbrk(0) is the live upper
		 * bound; brk only grows in the steady state, so the larger
		 * of the two is the safe outer edge.  A failed sbrk(0)
		 * falls back to the pre-fork heap_end.
		 */
		end = heap_end;
		cur = (unsigned long) sbrk(0);
		if (cur != (unsigned long) -1 && cur > end)
			end = cur;

		if (v >= heap_start && v < end)
			return true;
	}

	for (i = 0; i < nr_extra_heap_regions; i++) {
		if (v >= extra_heap_regions[i].start &&
		    v < extra_heap_regions[i].end)
			return true;
	}

	return false;
}

/*
 * Range-overlap variant of is_in_glibc_heap() with the opposite
 * unknown-bounds polarity: returns true when [addr, addr+len)
 * intersects the brk arena or any captured non-brk allocator
 * region (glibc mmap arenas, libasan primary / secondary / shadow,
 * scudo / jemalloc / tcmalloc tagged regions -- see
 * extra_heap_regions[] above).  Used by avoid_shared_buffer() to
 * redirect output-buffer syscall args away from any allocator-managed
 * memory: a fuzzed pointer pointing there lets the kernel scribble
 * chunk metadata, and the next malloc anywhere in trinity finds the
 * corruption and aborts.  Mirrors range_overlaps_shared() semantics:
 * a single byte of overlap is enough to redirect, and a fully unknown
 * layout (no [heap] line and no captured allocator regions) is treated
 * as no-overlap so we don't redirect every legitimate write.
 */
bool range_overlaps_libc_heap(unsigned long addr, unsigned long len)
{
	unsigned long end, hend, cur;
	unsigned int i;

	/* Treat wrapped ranges as overlapping so callers reject them. */
	if (len != 0 && addr > ULONG_MAX - len)
		return true;

	end = addr + len;
	if (end == addr)
		end = addr + 1;

	if (heap_start != 0) {
		/*
		 * Same brk-grew-past-snapshot story as
		 * is_in_glibc_heap(), with the same sbrk(0) for the live
		 * upper bound.  Missing the redirect here is the
		 * safety-critical failure mode: a fuzzed pointer landing
		 * in the brk extension above the cached heap_end gets
		 * through avoid_shared_buffer(), the kernel scribbles
		 * glibc chunk metadata in the extension, and the next
		 * malloc in the child aborts.
		 */
		hend = heap_end;
		cur = (unsigned long) sbrk(0);
		if (cur != (unsigned long) -1 && cur > hend)
			hend = cur;

		if (addr < hend && end > heap_start)
			return true;
	}

	/*
	 * Walk the captured non-brk allocator regions.  Each entry is
	 * a fixed [start, end) snapshot from heap_bounds_init(), which
	 * the parent runs once pre-fork and each child re-runs at the
	 * end of init_child() so glibc arenas that the child's own
	 * post-fork allocator storm spawned (per-thread mmap arenas,
	 * libasan shadow growth, secondary allocator regions tagged
	 * via PR_SET_VMA_ANON_NAME) make it into the snapshot before
	 * the syscall fuzz loop starts hammering pointers through this
	 * gate.  The captured VMAs are large reservations whose bounds
	 * don't shrink and rarely grow once the child is settled, so a
	 * single refresh per child closes the post-fork window without
	 * touching the hot path.
	 */
	for (i = 0; i < nr_extra_heap_regions; i++) {
		if (addr < extra_heap_regions[i].end &&
		    end > extra_heap_regions[i].start)
			return true;
	}

	/*
	 * Post-init secondary-mmap miss detector.  Falling through to
	 * here means brk and every captured slot rejected the range,
	 * but the query still falls inside the bounding box that spans
	 * the captured slots -- the canonical shape of a libc large-
	 * malloc that bypassed the primary allocator into a fresh
	 * one-VMA-per-alloc landing between two captured arenas after
	 * the heap_bounds_init() snapshot was taken.  Bump an
	 * observability counter so the rate is visible in dump_stats(),
	 * and after every HEAP_OUTSIDE_CACHE_REFRESH_THRESHOLD misses
	 * pay for one /proc/self/maps re-parse and rescan the (now
	 * fresh) extras for this same query.  A genuine post-init mmap
	 * promotes to a real overlap on the rescan and the redirect
	 * fires for the very call that triggered the refresh; a query
	 * inside the bbox that doesn't correspond to any allocator VMA
	 * (sparse extras layout) leaves the snapshot unchanged and the
	 * counter resets, capping the refresh cost at one
	 * /proc/self/maps walk per THRESHOLD misses.
	 */
	if (extra_heap_regions_bbox_end > extra_heap_regions_bbox_start &&
	    addr < extra_heap_regions_bbox_end &&
	    end > extra_heap_regions_bbox_start) {
		static unsigned int outside_cache_since_refresh;
		struct childdata *c;

		c = this_child();
		if (c != NULL && c->stats_ring != NULL)
			stats_ring_enqueue(c->stats_ring,
					   STATS_FIELD_HEAP_POINTER_OUTSIDE_CACHE,
					   0, 1);
		else
			parent_stats.heap_pointer_outside_cache++;

		if (++outside_cache_since_refresh >=
		    HEAP_OUTSIDE_CACHE_REFRESH_THRESHOLD) {
			outside_cache_since_refresh = 0;
			heap_bounds_init();

			for (i = 0; i < nr_extra_heap_regions; i++) {
				if (addr < extra_heap_regions[i].end &&
				    end > extra_heap_regions[i].start)
					return true;
			}
			/* Re-check the brk arena too: heap_bounds_init()
			 * re-read the [heap] line, which a snapshot taken
			 * before brk first grew did not have. */
			if (heap_start != 0) {
				unsigned long hend2 = heap_end;

				cur = (unsigned long) sbrk(0);
				if (cur != (unsigned long) -1 && cur > hend2)
					hend2 = cur;
				if (addr < hend2 && end > heap_start)
					return true;
			}
		}
	}

	return false;
}

/*
 * Fast-path inverse-polarity check: is [addr, addr+len) fully inside
 * the brk arena, or fully inside any single captured non-brk
 * allocator region?  Mirrors range_in_tracked_shared() for the heap
 * snapshot maintained by heap_bounds_init().  Used only by
 * range_readable_user() below -- not a sanitiser gate, so unknown
 * layout returns false (no cached extent implies no proof of
 * readability; the caller treats that as skip-copy).
 */
bool range_inside_libc_heap(unsigned long addr, unsigned long len)
{
	unsigned long end, hend, cur;
	unsigned int i;

	if (len != 0 && addr > ULONG_MAX - len)
		return false;

	end = addr + len;

	if (heap_start != 0) {
		hend = heap_end;
		cur = (unsigned long) sbrk(0);
		if (cur != (unsigned long) -1 && cur > hend)
			hend = cur;

		if (addr >= heap_start && end <= hend)
			return true;
	}

	for (i = 0; i < nr_extra_heap_regions; i++) {
		if (addr >= extra_heap_regions[i].start &&
		    end <= extra_heap_regions[i].end)
			return true;
	}

	return false;
}

/*
 * Diagnostic helper for the mm-syscall arg sanitisers.  Called from each
 * mm-syscall hook (madvise / mmap / mprotect / mremap /
 * remap_file_pages) AFTER the brk-overlap gate
 * (range_overlaps_libc_heap) has returned "not heap" for [addr, addr+len)
 * and the per-syscall sanitiser has finished any further addr rewrites.
 * Reads the break again and, if the address now proves to lie inside
 * the live brk arena, bumps a counter and (rate-limited) logs the
 * slipping syscall so the next live run pins exactly which call got
 * past the gate.  The gate reads the live break too, so a slip means
 * the address entered the arena after the gate judged it: a path that
 * skips the gate, a rewrite after it, or a brk grow in between.
 *
 * Pure observability -- does NOT rewrite the slipping addr (that would
 * pre-judge which gate is at fault; the log lets a real audit make
 * that call from fleet data).  Children inherit the rate-limiter via
 * the file-static counter; per-process limiter is fine for diagnostic
 * spam control.
 *
 *   @syscall_name : mm-syscall short name (madvise / mmap / ...).
 *   @addr, @len   : the (post-sanitise) range about to be handed to
 *                   the kernel.
 *   @detail       : per-syscall context arg -- madvise advice, mprotect
 *                   prot, mmap flags, etc.  Recorded verbatim in the
 *                   log line so the post-hoc filter can split by class.
 */
#define MM_GATE_SLIP_LOG_BURST		8
#define MM_GATE_SLIP_LOG_PERIOD		4096

void log_mm_syscall_post_gate_heap_slip(const char *syscall_name,
					unsigned long addr,
					unsigned long len,
					unsigned long detail)
{
	static unsigned int slip_log_count;
	struct childdata *c;
	unsigned long fresh_brk, end;
	unsigned int my_count;

	if (addr == 0 || len == 0)
		return;
	if (heap_start == 0)
		return;

	/* Wrap guard: a wrapped range is its own bug, not a brk slip. */
	if (addr > ULONG_MAX - len)
		return;

	/* Entirely below the brk base -- no way the gate is wrong here. */
	if (addr + len <= heap_start)
		return;

	fresh_brk = (unsigned long) sbrk(0);
	if (fresh_brk == (unsigned long) -1)
		return;

	end = fresh_brk;
	if (heap_end > end)
		end = heap_end;

	/* Fresh resample agrees with the gate: addr is above the live
	 * brk, so the gate was right to pass it through. */
	if (addr >= end)
		return;

	c = this_child();
	if (c != NULL && c->stats_ring != NULL)
		stats_ring_enqueue(c->stats_ring,
				   STATS_FIELD_MM_GATE_POST_SLIP, 0, 1);
	else
		parent_stats.mm_gate_post_slip++;

	my_count = __atomic_fetch_add(&slip_log_count, 1, __ATOMIC_RELAXED);
	if (my_count < MM_GATE_SLIP_LOG_BURST ||
	    ((my_count - MM_GATE_SLIP_LOG_BURST) %
	     MM_GATE_SLIP_LOG_PERIOD) == 0)
		outputerr("MM-GATE-POST-SLIP: %s addr=0x%lx len=0x%lx "
			  "detail=0x%lx heap_start=0x%lx heap_end=0x%lx "
			  "fresh_sbrk=0x%lx\n",
			  syscall_name, addr, len, detail, heap_start,
			  heap_end, fresh_brk);
}
