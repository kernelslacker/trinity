#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "arch.h"
#include "child.h"
#include "deferred-free.h"
#include "maps.h"
#include "maps-internal.h"
#include "rnd.h"
#include "utils.h"

/*
 * Destructor for OBJ_LOCAL mmap entries (init_child_mappings copies and
 * the children's own runtime mmaps).  The obj struct and the name string
 * both live on the calling process's private heap, so we use the regular
 * libc free path.
 */
void map_destructor(struct object *obj)
{
	struct map *map;
	size_t extent;

	map = &obj->map;
	/*
	 * clone_global_mmap_pool() propagates tracked_size onto OBJ_LOCAL
	 * FILE/TESTFILE entries cloned from a clamped mmap_fd() source, so
	 * the local-pool destructor sees the same map->size < VMA extent
	 * asymmetry as map_destructor_shared().  Release both the
	 * shared_regions[] slot and the VMA against the pre-clamp extent
	 * so the two halves stay in lock step; legacy callers that never
	 * clamped leave tracked_size == 0 and fall back to map->size.
	 */
	extent = map->tracked_size ? map->tracked_size : map->size;
	/*
	 * Ownership gate: only the struct map that CREATED the VMA is
	 * entitled to release it.  init_child_mappings() and
	 * clone_global_mmap_pool() build OBJ_LOCAL entries by copying
	 * m->ptr from OBJ_GLOBAL sources -- those cloned entries share
	 * the VMA with the still-live global owner and with any sibling
	 * child that also cloned from it, so untrack+munmap here would
	 * (a) release a shared_regions[] slot the global source still
	 * uses, and (b) leave the global's m->ptr pointing at freed VA.
	 * The next clone_global_mmap_pool() refill would then re-copy
	 * the stale pointer straight into the pool -- ASAN heap-buffer-
	 * overflow on the first downstream walker (read_mapping_reverse
	 * / dirty_mapping) that dereferences it.
	 *
	 * Runtime OBJ_LOCAL entries (post_mmap CHILD_ANON/MMAPED_FILE,
	 * mmap_lifecycle do_create) set owns_vma=true at creation and
	 * fall through to the untrack+munmap below; borrowed clones
	 * (owns_vma=false, the zero default) skip it and leak the VA
	 * for the rest of the child's run -- the global source will
	 * unmap it via map_destructor_shared() at process teardown.
	 * A missed untrack for a borrowed slot is silent: the shared_
	 * regions[] slot stays live under the global owner's registration.
	 *
	 * Range-validate map->ptr and cap extent before untrack+munmap.
	 * The obj-pool armor at get_map_handle (maps-pick.c) only
	 * validates the obj pointer; an in-place scribble of the map body
	 * via a fuzzed value-result syscall whose user buffer aliases a
	 * real, pool-resident obj can leave .ptr / .tracked_size wild while
	 * the obj-pointer gate still vouches for the slot.  munmap() on a
	 * wild (ptr, len) pair can collateral-unmap trinity's own
	 * bookkeeping (the armored deferred-free ring, shm regions);
	 * untrack_shared_region() with the same pair would also corrupt
	 * shared_regions[] bookkeeping by chance-matching an unrelated
	 * slot.  Mirror the existing get_map_handle guards: user VA band
	 * [0x10000, 0x800000000000) (maps-pick.c obj_ptr_in_user_va_band)
	 * and the GB(4) cap on size (maps-pick.c).  Skip the whole
	 * untrack+munmap pair on miss
	 * -- leaking the VA for the rest of the run is strictly safer
	 * than a wild unmap, and the name-free gate below still runs so
	 * the proven-ours name buffer is recycled.
	 */
	if (map->owns_vma &&
	    map->ptr != NULL &&
	    (uintptr_t)map->ptr >= 0x10000UL &&
	    (uintptr_t)map->ptr < 0x800000000000UL &&
	    extent != 0 && extent <= GB(4UL)) {
		untrack_shared_region((unsigned long)map->ptr, extent);
		munmap(map->ptr, extent);
	}
	/*
	 * Free the name via tracked_free_now(), not a bare free().  A bare
	 * free() releases the buffer to glibc but leaves its pointer in
	 * alloc_track[] -- the alloc_track_lookup() gate only tests
	 * membership, it does not consume the entry.  A later
	 * alloc_track_consume() (the deferred-free ring drain, or after
	 * glibc reuses the freed chunk for a new tracked allocation) then
	 * still returns true and free()s it a second time -- the ASAN
	 * bad-free observed at deferred-free.c:697.  tracked_free_now()
	 * consumes the alloc_track entry as it frees, skips ring-owned
	 * pointers so the ring's drain stays authoritative, and still
	 * leaks an unproven (scribbled) name because the consume gate
	 * rejects any pointer __zmalloc never produced -- "release what we
	 * own, leak the unproven".
	 */
	tracked_free_now(map->name);
	map->name = NULL;
}

/*
 * Destructor for OBJ_GLOBAL mmap entries created via mmap_fd() and
 * setup_initial_mappings().  The obj struct itself is freed by
 * release_obj() (which zeroes the chunk and routes it through
 * deferred-free); we only need to release the name string and
 * unmap the actual mapping here.
 */
void map_destructor_shared(struct object *obj)
{
	struct map *map;
	size_t extent;

	map = &obj->map;
	/*
	 * Both untrack_shared_region() and munmap() need the full VMA extent,
	 * not the consumer-walkable extent in map->size.
	 *
	 * untrack_shared_region() matches the (addr, len) pair recorded at
	 * track_shared_region() time exactly; a shorter len would leave the
	 * shared_regions[] slot in place and the bitmap bits past `len' would
	 * outlive the munmap below, blocking any subsequent VA recycle into
	 * legitimate fuzzed mm-syscalls.  munmap() with a shorter len under-
	 * unmaps the VMA: the past-clamp tail pages stay mapped until process
	 * exit, leaking address space and keeping the file's page-cache pin
	 * alive for entries the destructor is supposed to be releasing.
	 *
	 * mmap_fd() may clamp map->size down to the fstat-backed extent after
	 * the kernel mapped a wider VMA; the pre-clamp length lives in
	 * map->tracked_size for exactly these two calls.  Legacy callsites
	 * that pre-date the field leave tracked_size == 0; fall back to
	 * map->size for those (they set size to the real VMA extent because
	 * they never clamped).
	 */
	extent = map->tracked_size ? map->tracked_size : map->size;
	/*
	 * Same destructor-munmap gate as map_destructor() above: range-
	 * validate map->ptr and cap extent before untrack+munmap so an
	 * in-place .ptr / .tracked_size scribble cannot drive a wild
	 * unmap of trinity's own bookkeeping.  See map_destructor() for
	 * the full rationale.
	 */
	if (map->ptr != NULL &&
	    (uintptr_t)map->ptr >= 0x10000UL &&
	    (uintptr_t)map->ptr < 0x800000000000UL &&
	    extent != 0 && extent <= GB(4UL)) {
		untrack_shared_region((unsigned long)map->ptr, extent);
		munmap(map->ptr, extent);
	}
	/*
	 * Gate the name free on shared-heap residency and on an
	 * authoritative alloc-time length recorded in name_alloc_size.
	 * The local destructor uses alloc_track_lookup (libc heap); this
	 * variant's names live in the shared str heap (alloc_shared_pool,
	 * registered via shared_regions[]), so range_in_tracked_shared()
	 * is the matching residency check.
	 *
	 * The old code path derived the free size from strlen(map->name) +
	 * 1 for non-INITIAL_ANON names.  Those bytes live in a MAP_SHARED
	 * region that fuzzed syscalls can hand to the kernel as a user
	 * buffer -- a stomped NUL walked strlen off the slot's end (in
	 * the worst case past shared_str_heap_capacity, SEGV) before
	 * free_shared_str even saw the pointer, and even without a SEGV
	 * a fuzz-influenced size flowed into free_shared_str's leak-path
	 * memset.  name_alloc_size stashes the length passed at carve
	 * time on the parent-populated struct; use it instead so the
	 * fuzzer can no longer steer either the strlen read or the free
	 * size.  A zero or out-of-range value has no authoritative
	 * source -- leak the shared_str slot rather than steer the free
	 * path with a fuzzed quantity.  1024 is the largest bucketed
	 * size; above-bucket slots are bump-and-leak so their "correct"
	 * free-size is a no-op.
	 */
	if (map->name != NULL &&
	    range_in_tracked_shared((unsigned long)map->name, 1) &&
	    map->name_alloc_size != 0 &&
	    map->name_alloc_size <= 1024U) {
		free_shared_str(map->name, map->name_alloc_size);
	}
	map->name = NULL;
}

void map_dump(struct object *obj, enum obj_scope scope)
{
	struct map *m;
	char buf[32];

	m = &obj->map;

	sizeunit(m->size, buf, sizeof(buf));
	output(2, " start: %p size:%s  flags:%s%s  name: %s scope:%d\n",
		m->ptr, buf,
		(m->flags & MAP_SHARED) ? "shared" : "private",
		(m->flags & MAP_HUGETLB) ? ",hugetlb" : "",
		m->name, scope);
}

/*
 * Seed an OBJ_LOCAL OBJ_MMAP_* pool from the matching OBJ_GLOBAL
 * snapshot.  Used for the FILE / TESTFILE pools at fork; ANON has
 * its own open-coded loop because it hardcodes INITIAL_ANON on the
 * cloned entry (every ANON source is INITIAL_ANON anyway, but the
 * explicit assignment documents the post-fork lifecycle expected
 * by mprotect/mremap/munmap).  This helper instead propagates the
 * source map type so MMAPED_FILE entries stay tagged as such.
 */
void clone_global_mmap_pool(enum objecttype type)
{
	struct objhead *globalhead, *localhead;
	struct object *globalobj, *localobj;
	unsigned int idx, lidx;

	globalhead = get_objhead(OBJ_GLOBAL, type);
	if (globalhead == NULL || globalhead->array == NULL)
		return;

	/*
	 * localhead may be NULL on the very first call before
	 * init_child_mappings() ran; treat that as "nothing to dedup
	 * against" and append every entry.
	 */
	localhead = get_objhead(OBJ_LOCAL, type);

	for_each_obj(globalhead, globalobj, idx) {
		struct map *m = &globalobj->map;
		struct object *newobj;
		bool dup = false;

		if (m->name == NULL) {
			outputerr("clone_global_mmap_pool: skipping global map with NULL name (type %u)\n",
				  type);
			continue;
		}

		/*
		 * Dedup by ptr against the local head.  Global ANON ptrs
		 * are stable (set once at setup_initial_mappings, never
		 * replaced) and child-added post_mmap entries return
		 * unique mmap'd ptrs that cannot collide with a global
		 * slot, so a ptr match means we have already cloned this
		 * global entry on a prior refill.  Without this guard
		 * each refill appends N copies of every global entry,
		 * bloating per-child memory (leaked strdup'd names) and
		 * skewing future uniform draws.
		 */
		if (localhead != NULL && localhead->array != NULL) {
			for_each_obj(localhead, localobj, lidx) {
				if (localobj->map.ptr == m->ptr) {
					dup = true;
					/* Refresh the local obj in alloc_track[] so the validator
					 * LRU lookup at get_map_handle (mm/maps-pick.c) stays warm
					 * even when dedup skips a fresh __zmalloc_tracked.  Without
					 * this, dedup starves alloc_track and pool entries rotate
					 * out under churn (the 256->4096 alloc_track widen was outpaced 100x
					 * at full throughput). */
					alloc_track_refresh(localobj);
					break;
				}
			}
		}
		if (dup)
			continue;

		newobj = alloc_object();
		newobj->map.ptr = m->ptr;
		newobj->map.name = strdup(m->name);
		if (!newobj->map.name) {
			tracked_free_now(newobj);
			continue;
		}
		newobj->map.size = m->size;
		newobj->map.tracked_size = m->tracked_size;
		newobj->map.prot = m->prot;
		newobj->map.flags = m->flags;
		newobj->map.fd = m->fd;
		newobj->map.type = m->type;
		/*
		 * Borrowed VMA -- ptr is a copy of the OBJ_GLOBAL owner's
		 * pointer.  Only the global source is entitled to munmap +
		 * untrack_shared_region at destroy time.  See struct map's
		 * owns_vma comment.
		 */
		newobj->map.owns_vma = false;
		add_object(newobj, OBJ_LOCAL, type);
	}
}

/*
 * Cap each child's LOCAL mmap pools so the otherwise-dormant prune path
 * (prune_objects -> __prune_objects -> map_destructor -> munmap) runs.
 * With max_entries left at 0 the pool never prunes: every successful
 * fuzzed mmap()/memfd map adds an OBJ_LOCAL entry that is not reclaimed
 * until the child exits, so a long-lived child (canary / D-state-wedged)
 * pins gigabytes of resident shmem and OOMs a small box.  64 matches the
 * self-limit mmap_lifecycle already enforces (MAX_LIFECYCLE_MAPS) and
 * keeps plenty of pool diversity for mm coverage.  GLOBAL pools are
 * separately hard-capped at OBJ_GLOBAL_MAX; this is the missing LOCAL cap.
 */
#define MMAP_LOCAL_MAX_ENTRIES 64U

/*
 * Set up a childs local mapping list.
 * A child inherits the initial mappings, and will add to them
 * when it successfully completes mmap() calls.
 */
void init_child_mappings(void)
{
	struct objhead *head, *globalhead;
	struct object *globalobj;
	unsigned int idx;

	/*
	 * init_object_lists(OBJ_LOCAL, child) copies head->destroy from
	 * the matching OBJ_GLOBAL head into every OBJ_LOCAL head.  The
	 * OBJ_GLOBAL OBJ_MMAP_* heads are wired to map_destructor_shared
	 * (setup_initial_mappings for ANON, mmap_fd for FILE/TESTFILE),
	 * which calls free_shared_str() -- the shared-heap allocator --
	 * on map->name.  But OBJ_LOCAL entries created by post_mmap and
	 * by the global-pool clone in this routine allocate map->name
	 * with libc strdup(), so the inherited destructor would feed a
	 * libc-malloc'd pointer to free_shared_str() and corrupt the
	 * shared-heap metadata for every other child.
	 *
	 * Override the inherited destructor on ALL three local mmap
	 * pools to the libc-allocator destructor.  The ANON path was
	 * the only one already covered; FILE and TESTFILE were latent
	 * until the post_munmap pool-type fix landed and started
	 * routing those entries to destroy_object() with their real
	 * head.  Both must land together: fixing one without the other
	 * turns a latent bug into a live crash class.
	 */
	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_ANON);
	if (head == NULL)
		return;
	head->destroy = &map_destructor;
	head->dump = &map_dump;

	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_FILE);
	if (head != NULL) {
		head->destroy = &map_destructor;
		head->dump = &map_dump;
	}

	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_TESTFILE);
	if (head != NULL) {
		head->destroy = &map_destructor;
		head->dump = &map_dump;
	}

	globalhead = get_objhead(OBJ_GLOBAL, OBJ_MMAP_ANON);
	if (globalhead != NULL && globalhead->array != NULL) {
		/* Copy the initial mapping list to the child.
		 * Note we're only copying pointers here, the actual mmaps
		 * will be faulted into the child when they get accessed.
		 *
		 * Skip entries whose name pointer is bogus.  See child #9 spawn
		 * crash where m->name had been overwritten with 0x610000.  The
		 * iteration bound is provided by for_each_obj (array_capacity);
		 * no additional cap is needed.
		 */
		for_each_obj(globalhead, globalobj, idx) {
			struct map *m = &globalobj->map;
			struct object *newobj;

			if (m->name == NULL) {
				outputerr("init_child_mappings: skipping global map with NULL name\n");
				continue;
			}

			newobj = alloc_object();
			newobj->map.ptr = m->ptr;
			newobj->map.name = strdup(m->name);
			if (!newobj->map.name) {
				tracked_free_now(newobj);
				continue;
			}
			newobj->map.size = m->size;
			newobj->map.tracked_size = m->tracked_size;
			newobj->map.prot = m->prot;
			newobj->map.flags = m->flags;
			newobj->map.fd = m->fd;
			/* We leave type as 'INITIAL' until we change the mapping
			 * by mprotect/mremap/munmap etc..
			 */
			newobj->map.type = INITIAL_ANON;
			/*
			 * Borrowed VMA -- see clone_global_mmap_pool() above
			 * and struct map's owns_vma comment.  The global
			 * setup_initial_mappings() ANON entry we cloned from
			 * is the sole owner; pruning this clone must not munmap
			 * the still-live VMA the global source (and any sibling
			 * child that also cloned from it) points at.
			 */
			newobj->map.owns_vma = false;
			add_object(newobj, OBJ_LOCAL, OBJ_MMAP_ANON);
		}

		/*
		 * Seed the OBJ_LOCAL FILE and TESTFILE pools from their
		 * OBJ_GLOBAL snapshots too.  get_map_handle() picks the sub-pool
		 * uniformly from {ANON, FILE, TESTFILE}; without these clones
		 * two thirds of OBJ_LOCAL draws return NULL until lazy mmap
		 * shapes happen to add entries, which only the 1/8 file-fd path
		 * does for FILE and nothing does for TESTFILE.  Propagate the
		 * source m->type (MMAPED_FILE for both pools today) rather than
		 * forcing INITIAL_ANON so consumers can tell file mappings apart.
		 */
		clone_global_mmap_pool(OBJ_MMAP_FILE);
		clone_global_mmap_pool(OBJ_MMAP_TESTFILE);
	}

	/*
	 * Install the LOCAL prune cap AFTER seeding.  Setting max_entries
	 * before the clones would let add_object()'s per-insert
	 * prune_objects() hook fire once num_entries crossed the cap: the
	 * OBJ_GLOBAL OBJ_MMAP_ANON seed alone is 11 prot/flags variants x
	 * 9 mapping_sizes[] entries = 99 objects (plus optional hugetlb)
	 * versus a 64-entry cap, so the ONE_IN(10) prune gate would fire
	 * several times during init and evict a fraction of the initial
	 * diversity we just copied in.  Deferring the cap install lets the
	 * full seed land untouched; the cap still bounds fuzz-created
	 * post_mmap() growth thereafter, which is what it was added for.
	 */
	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_ANON);
	if (head != NULL)
		head->max_entries = MMAP_LOCAL_MAX_ENTRIES;
	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_FILE);
	if (head != NULL)
		head->max_entries = MMAP_LOCAL_MAX_ENTRIES;
	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_TESTFILE);
	if (head != NULL)
		head->max_entries = MMAP_LOCAL_MAX_ENTRIES;
}

/*
 * Set up a mmap object for an fd we already opened.
 */
void mmap_fd(int fd, const char *name, size_t len, int prot, enum obj_scope scope, enum objecttype type)
{
	struct objhead *head;
	struct object *obj;
	off_t offset;
	int retries = 0;

	/*
	 * Create an MMAP of the same fd.  OBJ_GLOBAL entries are added to
	 * shm-visible lists that children walk, so the obj struct AND the
	 * name string MUST live in shared memory — otherwise children
	 * dereference parent-private pointers and SEGV in libc string
	 * functions when they read the name (the bug class the rest of
	 * the OBJ_GLOBAL sweep closed).
	 */
	if (scope == OBJ_GLOBAL) {
		size_t namelen;

		obj = alloc_object();
		if (obj == NULL)
			return;
		/*
		 * Capture the length passed to alloc_shared_strdup() BEFORE
		 * publishing the pointer to the obj.  alloc_shared_strdup()
		 * carves strlen(name)+1 bytes; recording the same quantity
		 * here lets map_destructor_shared() free the slot without
		 * re-strlen()'ing the payload (which lives in fuzz-reachable
		 * shared memory -- a stomped NUL would drive strlen past the
		 * slot end).  Held in a local until after the alloc succeeds
		 * so a NULL return leaves name_alloc_size at 0, which the
		 * destructor treats as "no authoritative size, leak".
		 */
		namelen = strlen(name) + 1;
		obj->map.name = alloc_shared_strdup(name);
		if (obj->map.name == NULL) {
			deferred_free_enqueue(obj);
			return;
		}
		obj->map.name_alloc_size = namelen;
	} else {
		obj = alloc_object();
		obj->map.name = strdup(name);
		if (!obj->map.name) {
			deferred_free_enqueue(obj);
			return;
		}
	}
	obj->map.size = len;

retry_mmap:
	if (len == 0) {
		offset = 0;
		obj->map.size = page_size;
	} else
		offset = (obj->map.size > 0 ? rnd_modulo_u64(obj->map.size) : 0) & PAGE_MASK;

	obj->map.prot = prot;
	obj->map.fd = fd;
	obj->map.type = MMAPED_FILE;
	obj->map.owns_vma = true;
	/*
	 * Capture the flags word into a local before mmap() so the actual
	 * flags used for this mapping are stored on the obj.  Calling
	 * get_rand_mmap_flags() inline as the mmap() arg threw the bits
	 * away, leaving obj->map.flags at zero for every entry seeded
	 * through this path -- map_dump() and any flag-aware consumer
	 * then saw shared / hugetlb mappings as plain private ones.
	 * Mirrors the alloc_zero_map() pattern in mm/maps-initial.c. */
	{
		int mmap_flags = (int) get_rand_mmap_flags();

		obj->map.flags = mmap_flags;
		obj->map.ptr = mmap(NULL, obj->map.size, prot, mmap_flags,
				    fd, offset);
	}
	if (obj->map.ptr == MAP_FAILED) {
		retries++;
		if (retries == 100) {
			if (scope == OBJ_GLOBAL) {
				/*
				 * Use the alloc-time name_alloc_size stashed
				 * on the map when alloc_shared_strdup()
				 * returned above -- see map_destructor_shared()
				 * for why re-strlen()'ing a shared-heap payload
				 * at free time is unsafe.  A zero or out-of-
				 * range value means the alloc never completed
				 * (unreachable on this branch: we returned on
				 * NULL name above) or an in-place scribble
				 * zeroed the field -- leak the slot in either
				 * case rather than trust the fuzzable strlen.
				 */
				if (obj->map.name_alloc_size != 0 &&
				    obj->map.name_alloc_size <= 1024U)
					free_shared_str(obj->map.name,
							obj->map.name_alloc_size);
				obj->map.name = NULL;
				deferred_free_enqueue(obj);
			} else {
				free(obj->map.name);
				obj->map.name = NULL;
				deferred_free_enqueue(obj);
			}
			obj = NULL;
			return;
		} else
			goto retry_mmap;
	}

	/*
	 * obj->map.size currently records the length passed to mmap():
	 * for len > 0 the caller-supplied length, for len == 0 a forced
	 * page_size used only to give the obj a non-NULL ptr for type
	 * tracking.  Neither value is bounded against the chosen fd's
	 * actual backing extent.
	 *
	 * For len > 0 the offset above is a random page-aligned multiple
	 * in [0, len); the kernel happily creates a VMA covering pages
	 * past EOF when offset + len > st_size, but accessing those pages
	 * SIGBUSes with BUS_ADRERR.  For len == 0 we have no walkable
	 * extent at all -- the one-page mmap exists only as a handle.
	 *
	 * dirty_random_mapping (and other consumers that walk obj->map.size
	 * bytes from obj->map.ptr) burn the child on the first unbacked
	 * page, so clamp the recorded size to the in-bounds extent.  fstat
	 * failure or an empty regular file leaves no walkable pages -- gate
	 * downstream walkers off with size 0.  mmap_fd is reached only from
	 * regular-file paths, so st_size == 0 means a genuinely empty file
	 * (the special-fd carve-out used by post_mmap does not apply here).
	 */
	if (len == 0) {
		obj->map.size = 0;
	} else {
		struct stat st;

		if (fstat(fd, &st) != 0 || st.st_size == 0) {
			obj->map.size = 0;
		} else {
			off_t backed = (off_t) st.st_size - (off_t) offset;

			if (backed <= 0)
				obj->map.size = 0;
			else if ((unsigned long) backed < obj->map.size)
				obj->map.size = (unsigned long) backed & PAGE_MASK;
		}
	}

	/*
	 * A zero-clamped entry has no walkable extent and would only be
	 * rejected by every get_map_handle() consumer.  Drop it at the
	 * seed site instead of polluting the pool.
	 */
	if (obj->map.size == 0) {
		munmap(obj->map.ptr, len > 0 ? len : page_size);
		if (scope == OBJ_GLOBAL) {
			/* See the retries==100 branch above for why the
			 * alloc-time name_alloc_size is the authoritative
			 * source and re-strlen()'ing the shared-heap payload
			 * would be unsafe. */
			if (obj->map.name_alloc_size != 0 &&
			    obj->map.name_alloc_size <= 1024U)
				free_shared_str(obj->map.name,
						obj->map.name_alloc_size);
			obj->map.name = NULL;
			deferred_free_enqueue(obj);
		} else {
			free(obj->map.name);
			obj->map.name = NULL;
			deferred_free_enqueue(obj);
		}
		return;
	}

	/*
	 * Record the actual VMA extent the kernel mapped (len), not the
	 * fstat-clamped consumer-walkable extent in obj->map.size.  The clamp
	 * above shrinks map->size to the in-bounds backed region so dirty
	 * walkers stay inside real backing, but the kernel's VMA still covers
	 * the full `len' the mmap() call requested.  Defensive bookkeeping
	 * needs to know about the VMA extent: fuzzed kernel writes that land
	 * anywhere inside the VMA (past the backed tail included, where they
	 * SIGBUS rather than corrupt) must be recognised by
	 * range_overlaps_shared(), and the matching untrack at destroy time
	 * must release the same extent or the bitmap bits the tail claimed
	 * survive past munmap.  Length parity between this track call and the
	 * untrack in map_destructor_shared is enforced by both reading from
	 * obj->map.tracked_size.
	 */
	obj->map.tracked_size = len;
	track_shared_region((unsigned long)obj->map.ptr, len);

	head = get_objhead(scope, type);
	if (head != NULL) {
		head->dump = &map_dump;
		if (scope == OBJ_GLOBAL) {
			head->destroy = &map_destructor_shared;
		}
	}

	add_object(obj, scope, type);
	return;
}
