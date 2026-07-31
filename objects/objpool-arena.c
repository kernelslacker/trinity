/*
 * Per-child MAP_PRIVATE|MAP_ANON arena backing OBJ_LOCAL objpool storage
 * (struct object slots + head->array chunks) so a single track_shared_
 * region_tagged() registration protects the whole region against fuzzed
 * value-result kernel writes.
 *
 * The OBJ_LOCAL objpool storage previously came from the child's libc
 * heap via zmalloc_tracked().  range_overlaps_libc_heap() catches the
 * common case (brk arena + labeled non-brk allocator VMAs captured at
 * heap_bounds_init() time), but a glibc mmap arena spawned after
 * heap_bounds_init() falls outside both the pre-fork bbox and the brk
 * arena until the next miss-driven /proc/self/maps re-parse fires.
 * During that window a fuzzed pointer that ends up inside the new arena
 * gets past avoid_shared_buffer_out(), the kernel writes into head->array
 * or a struct object slot, and the next objpool_check() in maps-pick.c
 * (get_map_handle / addr_in_local_runtime_map) trips the SELF-CORRUPT
 * [mm:runtime-map:objpool] marker on the scribbled slot -- 46
 * SIGSEGV/run in run3, the dominant self-corruption crash driver.
 *
 * Routing all OBJ_LOCAL pool storage through a single tracked shared_
 * region closes the window unconditionally: range_overlaps_shared() sees
 * a byte-exact hit on any address inside the arena, and every scrub site
 * that already calls range_overlaps_shared() (blanket_address_scrub,
 * timer_create_sanitise's per-arg avoid_shared_buffer_out, the
 * scrub_iovec_for_kernel_write second pass, ...) relocates the fuzzed
 * pointer to a fresh writable-pool slot before the syscall issues.
 *
 * Design choices:
 *   - MAP_PRIVATE|MAP_ANON, parent-allocated pre-fork, COW-inherited by
 *     every child.  Same pattern as writable_pool_init() so the tracker
 *     entry registered once by the parent is visible to every child's
 *     range_overlaps_shared() call at the same virtual address.
 *   - Per-child bump cursor stored in struct childdata (owner-only
 *     writes, matches writable_pool_cursor precedent).  Parent uses a
 *     static local for pre-fork parent-context allocations that happen
 *     to route through here (rare -- OBJ_GLOBAL setup pre-dates the
 *     children[] alloc).
 *   - Bump-only, no free-list, no wrap.  A freed slot's bytes are
 *     zeroed by the caller (release_obj memset) but the cursor never
 *     rewinds; on exhaustion the caller falls back to zmalloc_tracked
 *     and pays the range_overlaps_libc_heap safety net instead.
 *     Recycling would need TTL to avoid reusing a slot underneath a
 *     stale reader (the deferred-free ring's job for libc-heap
 *     allocations); leaving it to a follow-up commit keeps this first
 *     slice small.
 *   - Arena size: OBJPOOL_ARENA_BYTES (8 MiB per child of virtual
 *     space).  Physical usage tracks touched pages only, so 200-wide
 *     fleets pay roughly (childdata_high-water * pages) not the full
 *     8 MiB per child.  Sized above the observed steady-state
 *     OBJ_LOCAL pool footprint (~30 objheads * ~100 objs * ~200 bytes
 *     ~= 600 KiB) with ~13x headroom for churn before the fallback
 *     path kicks in.
 *
 * The alloc_track hash/LRU registration is deliberately NOT called for
 * arena slots: it's a value-keyed prefilter for deferred_free_enqueue's
 * consume gate; arena slots never route through free(), so the
 * registration would just fill the ring with entries that no
 * deferred_free_enqueue call ever consumes.  The only consumer that
 * previously depended on alloc_track_lookup for obj-pool slots was the
 * old alloc_track LRU-based gate in mm/maps-pick.c, which is
 * documented above the current objpool_check() call as intentionally
 * replaced (see obj_pool_slot_check()).
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>

#include "child.h"
#include "objects.h"
#include "objects-internal.h"
#include "trinity.h"		/* outputerr */
#include "utils.h"		/* track_shared_region_tagged */

#define OBJPOOL_ARENA_BYTES	(8UL << 20)	/* 8 MiB */
#define OBJPOOL_ARENA_ALIGN	16UL		/* covers __alignof__(max_align_t) */

static unsigned char *objpool_arena_base;
static unsigned long objpool_arena_size;

void objpool_local_arena_init(void)
{
	void *p;

	p = mmap(NULL, OBJPOOL_ARENA_BYTES, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		outputerr("objpool_local_arena_init: mmap %lu failed: %s\n",
			  OBJPOOL_ARENA_BYTES, strerror(errno));
		return;
	}

	/*
	 * Register once, at the parent's pre-fork virtual address.  The
	 * shared_regions[] entry lives in alloc_shared()'d memory that every
	 * child inherits via fork, so every child's range_overlaps_shared()
	 * call sees the same tracked span at the same VA the child's COW
	 * view of the arena occupies.  Origin tag names the offender in the
	 * range_overlaps_shared_slow diagnostic under CONFIG_GUARD_SHARED;
	 * the untagged variant is functionally identical without the tag.
	 */
#ifdef CONFIG_GUARD_SHARED
	track_shared_region_tagged((unsigned long)p, OBJPOOL_ARENA_BYTES,
				   "objpool-local-arena");
#else
	track_shared_region((unsigned long)p, OBJPOOL_ARENA_BYTES);
#endif

	objpool_arena_base = p;
	objpool_arena_size = OBJPOOL_ARENA_BYTES;
}

/*
 * Return true if [p, p+size) falls entirely inside the arena.  Used by
 * release_obj() and add_object_grow_capacity() to choose the arena
 * memset/no-op path over the deferred_free_enqueue() path.  size==0
 * degenerates to a point-in-arena check.  A NULL base (init failed or
 * ran before this call) returns false so callers unconditionally take
 * the libc-heap path.
 */
bool objpool_local_arena_owns(const void *p, unsigned long size)
{
	unsigned long v = (unsigned long)p;
	unsigned long base;

	if (objpool_arena_base == NULL)
		return false;
	if (p == NULL)
		return false;

	base = (unsigned long)objpool_arena_base;
	if (v < base)
		return false;
	if (size > objpool_arena_size)
		return false;
	if (v > base + objpool_arena_size - size)
		return false;
	return true;
}

/*
 * Bump allocator.  Returns a zero-initialised slot of at least @size
 * bytes on success, NULL on any failure (arena unavailable, size
 * larger than the arena, or bump cursor exhausted).  A NULL return is
 * the caller's cue to fall back to zmalloc_tracked() -- the fallback
 * pointer routes through the normal deferred-free path at release
 * time and pays the range_overlaps_libc_heap safety net.
 *
 * Owner-only writes to the cursor: the child's own bump cursor lives
 * in struct childdata (COW-inherited zero from the parent's zero-init
 * pre-fork), and parent-context callers get a static local so the
 * pre-fork parent path (rare -- OBJ_GLOBAL setup runs before the
 * per-child ring alloc) does not race the child cursors.
 */
void *objpool_local_arena_alloc(unsigned long size)
{
	struct childdata *child;
	static unsigned long parent_cursor;
	unsigned long *cursor_p;
	unsigned long cursor, aligned, end;

	if (objpool_arena_base == NULL)
		return NULL;
	if (size == 0)
		return NULL;

	aligned = (size + (OBJPOOL_ARENA_ALIGN - 1)) & ~(OBJPOOL_ARENA_ALIGN - 1);
	if (aligned > objpool_arena_size)
		return NULL;

	child = this_child();
	cursor_p = (child != NULL) ? &child->objpool_arena_cursor
				   : &parent_cursor;
	cursor = *cursor_p;
	end = cursor + aligned;
	if (end > objpool_arena_size)
		return NULL;

	*cursor_p = end;

	/*
	 * The MAP_PRIVATE|MAP_ANON region is zero-fill on first fault; a
	 * bump-forward cursor guarantees the slot is untouched, so a memset
	 * would just re-zero already-zero pages.  Skip it -- the caller
	 * (alloc_object / add_object_grow_capacity) also zeros before use,
	 * so a stray non-zero byte from a hypothetical future recycler
	 * would still be neutralised at the current call sites.
	 */
	return objpool_arena_base + cursor;
}
