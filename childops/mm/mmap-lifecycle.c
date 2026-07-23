/*
 * mmap_lifecycle - rapidly create, dirty, and destroy anonymous mappings.
 *
 * Exercises the VMA allocator, merge/split paths, page fault handler,
 * and the mmap/munmap/mremap fast paths under pressure.  Each iteration
 * picks a random action: create a new anonymous mapping, mremap an
 * existing one, dirty one, or tear one down.
 */

#include <sys/mman.h>
#include <sys/syscall.h>
#include <string.h>

#include "arch.h"
#include "child.h"
#include "deferred-free.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "vma-pressure.h"

/* How many child-local mappings to allow before forcing teardown. */
#define MAX_LIFECYCLE_MAPS 64

static unsigned long pick_size(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0:	return page_size;
	case 1:	return page_size * (1 + rnd_modulo_u32(16));
	case 2:	return page_size * 64;
	case 3:	return MB(1);
	default: return RAND_ARRAY(mapping_sizes);
	}
}

/* Curated mmap prot combinations.  Always PROT_READ-bearing — a fully
 * unreadable anonymous map is uninteresting for the dirty/mremap/teardown
 * paths this op then drives, so we exclude PROT_NONE and the W-only /
 * X-only oddities mprotect_split is responsible for covering. */
static const unsigned long mmap_prot_combos[] = {
	PROT_READ,
	PROT_READ | PROT_WRITE,
	PROT_READ | PROT_EXEC,
	PROT_READ | PROT_WRITE | PROT_EXEC,
};

static int pick_prot(void)
{
	return (int)mmap_prot_combos[rnd_modulo_u32(ARRAY_SIZE(mmap_prot_combos))];
}

static bool do_create(void)
{
	struct object *obj;
	unsigned long size = pick_size();
	int prot = pick_prot();
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	void *p;

	if (ONE_IN(3))
		flags |= MAP_POPULATE;

	p = mmap(NULL, size, prot, (int)RAND_NEGATIVE_OR(flags), -1, 0);
	if (p == MAP_FAILED)
		return true;	/* non-fatal */

	obj = alloc_object();
	obj->map.ptr = p;
	obj->map.name = strdup("lifecycle");
	if (!obj->map.name) {
		munmap(p, size);
		tracked_free_now(obj);
		return true;	/* non-fatal */
	}
	obj->map.size = size;
	obj->map.prot = prot;
	obj->map.fd = -1;
	obj->map.type = CHILD_ANON;
	obj->map.owns_vma = true;
	add_object(obj, OBJ_LOCAL, OBJ_MMAP_ANON);

	/*
	 * Register the new mapping with shared_regions[] so that
	 * range_overlaps_shared() recognises it.  Without this the
	 * deferred-free gate in deferred_free_enqueue() lets a sanitise
	 * callback that handed back a get_writable_address() pointer --
	 * drawn from one of these OBJ_LOCAL OBJ_MMAP_ANON entries via
	 * get_map() -- slip through into libc free(), which then aborts
	 * inside _int_malloc on the bogus chunk metadata at ptr-16.
	 * The matching untrack lives in map_destructor (mm/maps.c), so
	 * destroy_object() on this entry releases the slot as well.
	 */
	track_shared_region((unsigned long)p, size);

	return true;
}

static bool do_mremap(void)
{
	struct object *obj;
	struct map *map;
	unsigned long old_ptr, old_size, new_size;
	void *p;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return true;

	map = &obj->map;

	/* Don't mremap initial mappings shared with siblings. */
	if (map->type == INITIAL_ANON)
		return true;

	old_ptr = (unsigned long)map->ptr;
	old_size = map->size;

	/*
	 * Drop our own shared_regions[] registration before the
	 * range_overlaps_shared() check; otherwise the entry we just
	 * added in do_create() would match and skip every mremap.
	 * Re-track on both the success and the failure paths so the
	 * OBJ_LOCAL slot always has a matching shared_regions[] entry.
	 */
	untrack_shared_region(old_ptr, old_size);

	if (range_overlaps_shared(old_ptr, old_size)) {
		track_shared_region(old_ptr, old_size);
		return true;
	}

	/* Grow or shrink. */
	if (RAND_BOOL())
		new_size = old_size + page_size * (1 + rnd_modulo_u32(16));
	else
		new_size = max((unsigned long)page_size, old_size / 2) & PAGE_MASK;

	if (new_size == 0)
		new_size = page_size;

	p = mremap(map->ptr, old_size, new_size, MREMAP_MAYMOVE);
	if (p == MAP_FAILED) {
		track_shared_region(old_ptr, old_size);
		return true;
	}

	map->ptr = p;
	map->size = new_size;
	/*
	 * Invalidate the get_writable_address() known_rw skip-cache: the
	 * slot's VMA was just relocated/resized, so any prior whole-mapping
	 * mprotect upgrade no longer covers what's at map->ptr.  Matches
	 * the clear post_mremap applies to mremap(2) callers.
	 */
	map->known_rw = false;
	track_shared_region((unsigned long)p, new_size);
	return true;
}

static bool do_teardown(void)
{
	struct object *obj;
	struct map *map;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return true;

	map = &obj->map;

	/* Never unmap initial mappings — other children share them. */
	if (map->type == INITIAL_ANON)
		return true;

	/*
	 * Drop our shared_regions[] registration before the
	 * range_overlaps_shared() check; the entry tracked by do_create()
	 * would otherwise match and block every teardown, saturating the
	 * pool at MAX_LIFECYCLE_MAPS.  map_destructor() also untracks --
	 * harmless second call, untrack misses are silent by design.
	 */
	untrack_shared_region((unsigned long)map->ptr, map->size);

	if (range_overlaps_shared((unsigned long)map->ptr, map->size))
		return true;

	destroy_object(obj, OBJ_LOCAL, OBJ_MMAP_ANON);
	return true;
}

static bool do_dirty(void)
{
	struct object *obj;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return true;

	dirty_mapping(&obj->map);
	return true;
}

bool mmap_lifecycle(struct childdata *child)
{
	struct objhead *head;
	unsigned int nr_maps;

	/* Global VMA-pressure backoff.  Skip the whole dispatch when
	 * latched: do_create / do_mremap can only add VMAs from here, and
	 * do_dirty / do_teardown alone aren't worth the dispatcher slot --
	 * the natural attrition (other childops returning, other children
	 * exiting) trims the count down to LO%% on its own. */
	if (vma_pressure_is_high())
		return true;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_ANON);
	if (head == NULL)
		return false;
	nr_maps = head->num_entries;

	if (valid_op) {
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);
	}

	/*
	 * Bias toward creation when we have few maps,
	 * toward teardown when we have many.
	 */
	if (nr_maps < 4) {
		do_create();
	} else if (nr_maps >= MAX_LIFECYCLE_MAPS) {
		do_teardown();
	} else {
		switch (rnd_modulo_u32(10)) {
		case 0 ... 3:	do_create();	break;
		case 4 ... 5:	do_mremap();	break;
		case 6 ... 7:	do_dirty();	break;
		case 8 ... 9:	do_teardown();	break;
		}
	}

	return true;
}
