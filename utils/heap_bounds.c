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
 * consumers also consult sbrk(0) for the current break.  Zero start
 * means we never found a [heap] line; in that case is_in_glibc_heap()
 * falls back to "always true" so we don't reject legitimate frees on
 * platforms or builds where glibc has chosen an mmap-only allocation
 * strategy and the brk arena is empty.
 */
static unsigned long heap_start;
static unsigned long heap_end;

/*
 * Per-child cached snapshot of sbrk(0), refreshed at heap_bounds_init()
 * time and then on every BRK_REFRESH_INTERVAL alloc_object() call via
 * heap_brk_maybe_refresh().  Used by is_in_glibc_heap() and
 * range_overlaps_libc_heap() instead of a per-call sbrk(0) -- those
 * gates fire on every deferred-free check and every random-address
 * generation, and the syscall-per-call was showing up in profiles.
 *
 * Staleness is bounded by the refresh cadence: in the worst case a
 * brk grow that happens between refreshes is invisible until the next
 * refresh fires, so a fuzzed pointer that lands in the extension is
 * not detected as heap-internal during that window.  brk grows in
 * page-or-larger chunks at a much lower rate than alloc_object() is
 * called (most allocations are served from the existing arena), so
 * the window is small in absolute address space.  Refresh tied to
 * alloc_object() means a brk grow caused by an allocation gets caught
 * by the next refresh that fires, and refresh-on-zero ensures
 * pre-init callers see "unknown extent" rather than a stale value.
 */
#define BRK_REFRESH_INTERVAL 64
static unsigned long cached_brk_end;
static unsigned int brk_refresh_counter;

/*
 * Upper VA at which the self-correcting brk re-test in
 * is_in_glibc_heap() and range_overlaps_libc_heap() stops paying
 * one sbrk(0) to resample the live break.  Any addr that sits at or
 * above the cached upper bound AND below this ceiling is plausibly
 * inside a brk extension that the cache hasn't caught up with;
 * addr >= ceiling is unambiguously not-heap (kernel VA, non-canonical)
 * and skips the syscall.
 *
 * Prior revisions capped the re-test with a fixed 256 MiB slack above
 * cached_brk_end.  That ceiling was tight enough that non-alloc_object()
 * traffic -- cmp-hint / RedQueen pool inflation, sequence record growth
 * -- could extend live brk past cached_brk_end + 256 MiB between
 * BRK_REFRESH_INTERVAL ticks, opening a window where a fuzzed
 * mmap(MAP_FIXED, PROT_READ) landing in the live-brk extension sailed
 * past the guard and stamped a read-only page on brk arena bookkeeping.
 * The downstream get_writable_address() upgrade then stored
 * map->known_rw=true on the now-RO page and the child took SEGV_ACCERR.
 *
 * The new ceiling is the user/kernel split (0x800000000000UL on
 * x86_64): below it, an address is canonical userspace and the
 * resample is cheap insurance against the staleness window; at or
 * above it, the address is kernel-VA or non-canonical and no sbrk(0)
 * will ever vouch for it.  The resampled live_brk back-fills
 * cached_brk_end so a workload that keeps hammering similar addresses
 * benefits from the freshly-refreshed cache on subsequent calls.
 */
#define HEAP_BRK_RETEST_CEILING		0x800000000000UL

static void heap_brk_refresh(void)
{
	unsigned long cur = (unsigned long) sbrk(0);

	if (cur != (unsigned long) -1)
		cached_brk_end = cur;
}

void heap_brk_maybe_refresh(void)
{
	if (++brk_refresh_counter < BRK_REFRESH_INTERVAL)
		return;
	brk_refresh_counter = 0;
	heap_brk_refresh();
}

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

	/*
	 * Prime the brk cache so the first is_in_glibc_heap() /
	 * range_overlaps_libc_heap() doesn't see 0.
	 */
	heap_brk_refresh();
}

/*
 * Bounds check: is @p inside any captured glibc-managed allocator
 * region?  Accepts the cached brk arena AND the labeled non-brk
 * allocator regions stashed by heap_bounds_init() (glibc mmap arenas,
 * libasan primary/secondary/shadow, scudo / jemalloc / tcmalloc
 * tagged regions -- see extra_heap_regions[]).  Returns true if no
 * allocator extent is known at all (init found neither a [heap] line
 * nor any [anon:NAME] regions) so the caller treats the validator as
 * permissive in that case.
 *
 * Earlier revisions only checked the brk arena, which silently
 * rejected legitimate frees of two important pointer classes:
 *   - allocations above MMAP_THRESHOLD (default 128 KiB), which glibc
 *     services from mmap'd arenas rather than brk, and
 *   - every allocation under ASAN, whose libasan-runtime allocator
 *     hands back chunks from its shadow-mapped pools outside brk.
 * The high deferred_free_reject rate seen in ASAN runs was this gate
 * dropping valid zmalloc() results.
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
		 * can extend brk past it, so the cached_brk_end snapshot
		 * (refreshed periodically off alloc_object() via
		 * heap_brk_maybe_refresh()) is the live upper bound; brk
		 * only grows in the steady state, so the larger of the two
		 * is the safe outer edge.  cached_brk_end is 0 before its
		 * first refresh and after a sbrk(0) failure -- the max()
		 * falls back to the pre-fork heap_end in that case.
		 */
		end = heap_end;
		cur = cached_brk_end;
		if (cur > end)
			end = cur;

		if (v >= heap_start && v < end)
			return true;

		/*
		 * Mirror of the self-correcting brk re-test in
		 * range_overlaps_libc_heap().  The cached snapshot just
		 * judged this pointer not-heap, but brk may have grown past
		 * cached_brk_end since the last heap_brk_maybe_refresh()
		 * tick (heavy non-alloc_object() allocator traffic outruns
		 * the alloc-driven refresh cadence).  Without the re-test, a
		 * deferred-free backstop that lands in [cached_brk_end,
		 * live_brk) marks a real heap chunk as not-heap and silently
		 * drops the free.  Pay one sbrk(0) when the pointer sits at
		 * or above the cached bound but below the user/kernel split
		 * (HEAP_BRK_RETEST_CEILING -- wild-high / kernel-VA / non-
		 * canonical pointers skip the syscall), refresh the cache,
		 * and re-check; return true if it now falls in the live
		 * arena.  The fixed 256 MiB slack the prior revision used
		 * was tight enough that cmp-hint / RedQueen traffic could
		 * outrun it between refreshes -- see HEAP_BRK_RETEST_CEILING.
		 */
		if (v >= end && v < HEAP_BRK_RETEST_CEILING) {
			unsigned long live_brk = (unsigned long) sbrk(0);

			if (live_brk != (unsigned long) -1) {
				if (live_brk > cached_brk_end)
					cached_brk_end = live_brk;
				if (live_brk > end)
					end = live_brk;
				if (v >= heap_start && v < end) {
					struct childdata *c = this_child();

					if (c != NULL && c->stats_ring != NULL)
						stats_ring_enqueue(c->stats_ring,
								   STATS_FIELD_HEAP_BRK_STALE_WINDOW_HIT,
								   0, 1);
					else
						parent_stats.heap_brk_stale_window_hit++;
					return true;
				}
			}
		}
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
 * intersects the cached brk arena or any captured non-brk allocator
 * region (glibc mmap arenas, libasan primary / secondary / shadow,
 * scudo / jemalloc / tcmalloc tagged regions -- see
 * extra_heap_regions[] above).  Used by avoid_shared_buffer() to
 * redirect output-buffer syscall args away from any allocator-managed
 * memory: a fuzzed pointer pointing there lets the kernel scribble
 * chunk metadata, and the next malloc anywhere in trinity finds the
 * corruption and aborts (the cluster from the overnight asan-self-
 * kill triage).  Mirrors range_overlaps_shared() semantics: a single
 * byte of overlap is enough to redirect, and a fully unknown layout
 * (no [heap] line and no captured allocator regions) is treated as
 * no-overlap so we don't redirect every legitimate write.
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
		 * is_in_glibc_heap(), with the same cached_brk_end
		 * snapshot for the live upper bound.  Missing the
		 * redirect here is the safety-critical failure mode: a
		 * fuzzed pointer landing in the brk extension above the
		 * cached heap_end gets through avoid_shared_buffer(), the
		 * kernel scribbles glibc chunk metadata in the extension,
		 * and the next malloc in the child aborts.  The cache
		 * staleness window (one BRK_REFRESH_INTERVAL of
		 * alloc_object() calls) is bounded by the refresh cadence
		 * driven off the alloc path -- a brk grow caused by an
		 * allocation gets picked up within INTERVAL allocations.
		 */
		hend = heap_end;
		cur = cached_brk_end;
		if (cur > hend)
			hend = cur;

		if (addr < hend && end > heap_start)
			return true;

		/*
		 * Self-correcting brk re-test.  The cached snapshot just
		 * judged this address not-heap, but brk may have grown past
		 * cached_brk_end since the last heap_brk_maybe_refresh()
		 * tick.  Heavy non-alloc_object() allocator traffic
		 * (cmp-hint / RedQueen tables, sequence record growth)
		 * extends the real brk without ticking the alloc-driven
		 * refresh, opening a window where glibc's top chunk -- or a
		 * brk-arena bookkeeping page -- sits in [cached_brk_end,
		 * live_brk) and a fuzzed output / MAP_FIXED address in that
		 * band gets handed to the kernel instead of being
		 * relocated.  Symptoms: the kernel scribbles top->size and
		 * the next malloc anywhere in the child aborts with
		 * "malloc(): corrupted top size"; or a fuzzed
		 * mmap(MAP_FIXED, PROT_READ) lands on brk arena and the
		 * next get_writable_address() upgrade SEGV_ACCERRs on the
		 * known_rw=true store.  Pay one sbrk(0) when the address
		 * sits at or above the cached bound but below the
		 * user/kernel split (HEAP_BRK_RETEST_CEILING -- wild-high /
		 * kernel-VA / non-canonical addresses skip the syscall),
		 * refresh the cache, and re-test the brk arm; if the
		 * address now falls in the live arena, redirect it (return
		 * true).  Prior revision capped this at a fixed 256 MiB
		 * slack above hend, which the cmp-hint / RedQueen traffic
		 * outran between refreshes -- see HEAP_BRK_RETEST_CEILING.
		 * The counter, kept in place, signals the fix firing.
		 */
		if (addr >= hend && addr < HEAP_BRK_RETEST_CEILING) {
			unsigned long live_brk = (unsigned long) sbrk(0);

			if (live_brk != (unsigned long) -1) {
				if (live_brk > cached_brk_end)
					cached_brk_end = live_brk;
				if (live_brk > hend)
					hend = live_brk;
				if (addr < hend && end > heap_start) {
					struct childdata *c = this_child();

					if (c != NULL && c->stats_ring != NULL)
						stats_ring_enqueue(c->stats_ring,
								   STATS_FIELD_HEAP_BRK_STALE_WINDOW_HIT,
								   0, 1);
					else
						parent_stats.heap_brk_stale_window_hit++;
					return true;
				}
			}
		}
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
			 * refreshes the brk cache as well, so a query that
			 * tripped because cached_brk_end was stale now
			 * resolves cleanly. */
			if (heap_start != 0) {
				unsigned long hend2 = heap_end;

				if (cached_brk_end > hend2)
					hend2 = cached_brk_end;
				if (addr < hend2 && end > heap_start)
					return true;
			}
		}
	}

	return false;
}

/*
 * Fast-path inverse-polarity check: is [addr, addr+len) fully inside
 * the cached brk arena, or fully inside any single captured non-brk
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
		cur = cached_brk_end;
		if (cur > hend)
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
 * mm-syscall hook (madvise / mmap / mprotect / mremap / mseal /
 * remap_file_pages) AFTER the brk-overlap gate
 * (range_overlaps_libc_heap) has returned "not heap" for [addr, addr+len)
 * and the per-syscall sanitiser has finished any further addr rewrites.
 * Pays one fresh sbrk(0) and, if the address now proves to lie inside
 * the live brk arena, bumps a counter and (rate-limited) logs the
 * slipping syscall so the next live run pins exactly which call passed
 * the gate with a stale snapshot.
 *
 * Two prior rounds widened the gate without pinning the slipping
 * syscall directly: the first capped the re-test at HEAP_BRK_STALE_
 * SLACK_BYTES (256 MiB) of slack above cached_brk_end, then the
 * widening to HEAP_BRK_RETEST_CEILING raised the ceiling to the
 * user/kernel split.  The live fleet kept faulting on RO-page writes
 * and glibc check_uid SIGABRTs anyway, which means a path either still
 * skips the re-test or there is a sanitise->syscall race the gate
 * never sees.  This helper makes the next round of triage data-driven
 * rather than another speculative widening.
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

	/* Wild-high / kernel-VA / non-canonical addrs cannot be heap. */
	if (addr >= HEAP_BRK_RETEST_CEILING)
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
	if (cached_brk_end > end)
		end = cached_brk_end;

	/* Fresh resample agrees with the gate: addr is above the live
	 * brk, so the gate was right to pass it through. */
	if (addr >= end)
		return;

	/* Back-fill the cache: we paid the syscall, no reason not to. */
	if (fresh_brk > cached_brk_end)
		cached_brk_end = fresh_brk;

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
			  "cached_brk_end=0x%lx fresh_sbrk=0x%lx\n",
			  syscall_name, addr, len, detail, heap_start,
			  heap_end, cached_brk_end, fresh_brk);
}
