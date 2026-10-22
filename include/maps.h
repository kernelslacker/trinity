#pragma once

#include <limits.h>
#include <stdbool.h>
#include "compiler.h"
#include "types.h"
#include "list.h"
#include "object-types.h"

#define INITIAL_ANON 1
#define CHILD_ANON 2
#define MMAPED_FILE 3

struct map {
	void *ptr;
	char *name;
	/*
	 * size:         consumer-walkable extent (post-clamp).  Fuzzed picks
	 *               bound by this -- dirty_mapping(), get_writable_address()
	 *               and other walkers stay inside [ptr, ptr+size) to avoid
	 *               SIGBUS on file-backed maps whose VMA covers past-EOF
	 *               pages.  For an empty / unbacked file this is 0.
	 *
	 * tracked_size: VMA extent passed to track_shared_region() at create
	 *               time.  Equals the length the kernel actually mapped and
	 *               is what untrack_shared_region() must be called with at
	 *               teardown -- the shared_regions[] tracker matches the
	 *               (addr, len) pair exactly; an under-sized untrack drops
	 *               the registration silently and the bitmap bits the
	 *               oversize tail claimed survive past the munmap that
	 *               released their VA.  Equals size for non-clamped
	 *               mappings (alloc_zero_map() ANON, try_alloc_zero_map()
	 *               HUGETLB).  A zero value is treated as "not set" by
	 *               map_destructor_shared() which falls back to size --
	 *               that keeps legacy callsites that pre-date this field
	 *               working unchanged, but is a fragile fallback: any new
	 *               code path that registers a tracked region must set
	 *               tracked_size explicitly.
	 */
	unsigned long size;
	unsigned long tracked_size;
	int prot;
	int flags;
	int fd;
	unsigned char type;
	/*
	 * VMA ownership.  true when this struct map created the VMA
	 * (setup_initial_mappings, mmap_fd, mmap_lifecycle do_create,
	 * post_mmap runtime creations); false when the VMA pointer was
	 * COPIED from another struct map (init_child_mappings ANON clone,
	 * clone_global_mmap_pool for ANON refills and FILE/TESTFILE seed).
	 * Only the true owner is allowed to munmap + untrack_shared_region
	 * at destroy time -- a clone destroying the borrowed VMA unmaps the
	 * address the global source still holds a live pointer to, and a
	 * later refill clones that stale pointer straight back into the
	 * pool (ASAN heap-buffer-overflow when a downstream walker touches
	 * the freed VA).
	 *
	 * NOT derivable from map->type: cloned MMAPED_FILE entries and
	 * runtime-created MMAPED_FILE entries share the same type tag and
	 * only this field distinguishes them.  Explicit assignment at every
	 * producer site is required -- the zero default is "borrowed" so an
	 * unset field errs safe (leak a VA rather than double-unmap).
	 */
	bool owns_vma;
	/*
	 * Hot-path skip-cache for get_writable_address(): set true on a
	 * successful whole-mapping mprotect(PROT_READ|PROT_WRITE) upgrade
	 * inside that function, false everywhere else.  Future calls that
	 * hit the bit can skip both the mprotect upgrade syscall and the
	 * mincore() VMA-presence probe -- the slot has been vouched RW
	 * and no invalidation event has fired since.
	 *
	 * Cleared by every code path that can change the slot's prot or
	 * VMA state out from under the cache:
	 *   - post_munmap (slot's VMA was unmapped, in whole or in part)
	 *   - post_mprotect (sibling mprotect changed the cached invariant)
	 *   - mprotect-split childop (raw mprotect that bypasses post hooks)
	 *   - the mprotect failure arm of get_writable_address itself
	 *     (don't lie about a slot we just failed to upgrade)
	 *
	 * False-negative (cache misses when the slot is actually still RW)
	 * is fine -- we eat one mprotect.  False-positive (vouching RW when
	 * the VMA was torn down) hands the caller a pointer that SEGVs on
	 * first store, so the invalidation hooks above must be exhaustive.
	 */
	bool known_rw;
};

#define NR_MAPPING_SIZES 9
extern unsigned long mapping_sizes[NR_MAPPING_SIZES];

struct object;
void map_destructor(struct object *obj);
void map_destructor_shared(struct object *obj);
void map_dump(struct object *obj, enum obj_scope scope);

void setup_initial_mappings(void);

struct map * get_map(void) __must_check;
struct map * get_map_with_prot(int required_prot) __must_check;
struct map * get_anon_map_with_prot(int required_prot) __must_check;

/*
 * Lightweight handle for an entry in the OBJ_MMAP_* pools.  Post-
 * Stage-5 every pool lives in private heap so there is no concurrent
 * destroyer to coordinate with; validate_map_handle() collapses to a
 * NULL check.  Kept as a thin wrapper rather than inlining so callers
 * that already pass a handle around (multi-frame arg-gen paths,
 * iovec builders) don't need to change shape.
 */
struct map_handle {
	struct map *map;
	enum objecttype type;
	enum obj_scope scope;
};

bool get_map_handle(struct map_handle *h) __must_check;
bool validate_map_handle(struct map_handle *h) __must_check;

/*
 * Map an OBJ_MMAP_* pool type to its bit position in
 * childdata.mmap_pool_nonempty_mask, or -1 for any other type.
 * Inlined so the 0<->1 nonempty-transition maintenance in add_object_publish /
 * __destroy_object stays free of an out-of-line call on the hot
 * publish/destroy paths.
 */
static inline int mmap_pool_bit_for_type(enum objecttype type)
{
	switch (type) {
	case OBJ_MMAP_ANON:	return 0;
	case OBJ_MMAP_FILE:	return 1;
	case OBJ_MMAP_TESTFILE:	return 2;
	default:		return -1;
	}
}

/*
 * Process-local ownership validator for runtime mmap() results.
 * Walks the current child's OBJ_LOCAL OBJ_MMAP_* pool and returns true
 * iff [addr, addr+len) is fully contained in at least one runtime
 * mapping the child created itself (CHILD_ANON / MMAPED_FILE entries
 * seeded by post_mmap()).  Used by get_writable_address() as a
 * second-chance acceptance test when range_in_tracked_shared() rejects:
 * runtime mmap results are not registered in shared_regions[] (which
 * exists for self-protection of trinity bookkeeping), so the global
 * tracker cannot validate them.
 *
 * INITIAL_ANON OBJ_LOCAL entries alias the global initial-mapping ptrs
 * and are already covered by range_in_tracked_shared(); this helper
 * intentionally skips them so the two acceptance paths stay disjoint.
 */
bool addr_in_local_runtime_map(unsigned long addr, unsigned long len) __must_check;

/*
 * Populate rec->a1 / rec->a2 from a randomly-picked OBJ_MMAP_* entry
 * and return the underlying map.  When out_type is non-NULL, the
 * helper additionally walks the three OBJ_LOCAL OBJ_MMAP_* pools to
 * identify which pool the returned obj belongs to and stores the
 * matching objecttype there.  Callers that need to destroy the obj
 * via destroy_object() must pass the resolved type so the destroy
 * lookup hits the right head; callers that only sample (mincore,
 * madvise, mlock, mprotect, ...) pass NULL.
 *
 * If no pool match is found (looks-like-real map pointer but obj not
 * currently registered in any local mmap pool -- e.g. a wholesale
 * stomp into rec->a1 that survived looks_like_corrupted_ptr) the
 * stored type defaults to OBJ_NONE and the caller is expected to
 * treat that as a destroy-not-safe signal.
 */
struct map * common_set_mmap_ptr_len(enum objecttype *out_type);

void dirty_mapping(struct map *map);
void dirty_random_mapping(void);

struct faultfn {
	void (*func)(struct map *map);
};

void random_map_readfn(struct map *map);
void random_map_writefn(struct map *map);

unsigned long get_rand_mmap_flags(void);

void mmap_fd(int fd, const char *name, size_t len, int prot, enum obj_scope scope, enum objecttype type);

bool proc_maps_check(unsigned long addr, unsigned long len,
		     int expected_prot, bool expect_present);

/*
 * Soft-invalidate every OBJ_LOCAL OBJ_MMAP_* entry whose mapped extent
 * overlaps [addr, addr+len).  Mirrors the conservative map->prot=0
 * invalidate post_munmap's sub-range branch and post_mprotect already
 * apply: get_map_with_prot() then skips the entry so the next consumer
 * (memory_pressure / iouring_* / madvise_pattern_cycler) cannot be
 * handed a tracked map pointer whose pages have been zeroed or
 * hole-punched by an unrelated syscall.  Returns the number of entries
 * the invalidate covered.  The VMA itself is left in place -- the
 * caller's syscall (madvise / fallocate / ftruncate) did not unmap it,
 * only modified its content, so we have no licence to munmap behind
 * the caller's back.
 */
unsigned int invalidate_obj_mmap_in_range(unsigned long addr,
					  unsigned long len);

/*
 * Same soft invalidate but matched by backing fd rather than virtual
 * address.  Walks the OBJ_LOCAL OBJ_MMAP_FILE and OBJ_MMAP_TESTFILE
 * pools and clears map->prot on every entry whose map->fd == fd; the
 * ANON pool is skipped (its map->fd is -1).  Used by post handlers
 * for syscalls that mutate file content at an offset (fallocate
 * hole-punch / range-zero, ftruncate shrink) where the affected file
 * range cannot be matched against the tracked virtual extent because
 * struct map carries no file-offset bookkeeping.  Returns the number
 * of entries the invalidate covered.
 */
unsigned int invalidate_obj_mmap_by_fd(int fd);
