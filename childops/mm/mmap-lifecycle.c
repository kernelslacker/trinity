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
#include "childop-outcome.h"
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

static unsigned long do_create(void)
{
	struct object *obj;
	unsigned long size = pick_size();
	int prot = pick_prot();
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	unsigned long direct_calls = 0;
	void *p;

	if (ONE_IN(3))
		flags |= MAP_POPULATE;

	direct_calls++;
	p = mmap(NULL, size, prot, (int)RAND_NEGATIVE_OR(flags), -1, 0);
	if (p == MAP_FAILED)
		return direct_calls;	/* non-fatal */

	obj = alloc_object();
	obj->map.ptr = p;
	obj->map.name = strdup("lifecycle");
	if (!obj->map.name) {
		direct_calls++;
		munmap(p, size);
		tracked_free_now(obj);
		return direct_calls;	/* non-fatal */
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
	 * The matching untrack lives in map_destructor (mm/maps-lifecycle.c), so
	 * destroy_object() on this entry releases the slot as well.
	 */
	track_shared_region((unsigned long)p, size);

	return direct_calls;
}

static unsigned long do_mremap(void)
{
	struct object *obj;
	struct map *map;
	unsigned long old_ptr, old_size, new_size;
	void *p;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return 0;

	map = &obj->map;

	/* Don't mremap initial mappings shared with siblings. */
	if (map->type == INITIAL_ANON)
		return 0;

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
		return 0;
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
		return 1;
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
	return 1;
}

static unsigned long do_teardown(void)
{
	struct object *obj;
	struct map *map;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return 0;

	map = &obj->map;

	/* Never unmap initial mappings — other children share them. */
	if (map->type == INITIAL_ANON)
		return 0;

	/*
	 * Drop our shared_regions[] registration before the
	 * range_overlaps_shared() check; the entry tracked by do_create()
	 * would otherwise match and block every teardown, saturating the
	 * pool at MAX_LIFECYCLE_MAPS.  map_destructor() also untracks --
	 * harmless second call, untrack misses are silent by design.
	 */
	untrack_shared_region((unsigned long)map->ptr, map->size);

	if (range_overlaps_shared((unsigned long)map->ptr, map->size))
		return 0;

	/*
	 * destroy_object -> map_destructor -> munmap.  do_create sets
	 * owns_vma=true on every OBJ_LOCAL entry it adds, so the
	 * destructor's ownership gate lets the munmap fire; count 1.
	 */
	destroy_object(obj, OBJ_LOCAL, OBJ_MMAP_ANON);
	return 1;
}

static unsigned long do_dirty(void)
{
	struct object *obj;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return 0;

	dirty_mapping(&obj->map);
	return 0;
}

bool mmap_lifecycle(struct childdata *child)
{
	struct objhead *head;
	unsigned int nr_maps;
	/* Local tally of the direct mmap/mremap/munmap syscalls this
	 * invocation actually issued.  Bumped by each do_* helper and
	 * published once to shm at op-exit via
	 * childop_direct_syscalls_add() so the hot path pays one atomic
	 * add per invocation instead of per-syscall.  Mirrors the
	 * pipe_thrash reporter pattern. */
	unsigned long direct_calls = 0;

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
		direct_calls += do_create();
	} else if (nr_maps >= MAX_LIFECYCLE_MAPS) {
		direct_calls += do_teardown();
	} else {
		switch (rnd_modulo_u32(10)) {
		case 0 ... 3:	direct_calls += do_create();	break;
		case 4 ... 5:	direct_calls += do_mremap();	break;
		case 6 ... 7:	direct_calls += do_dirty();	break;
		case 8 ... 9:	direct_calls += do_teardown();	break;
		}
	}

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
