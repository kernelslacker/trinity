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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "effector-map.h"
#include "maps.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* How many child-local mappings to allow before forcing teardown. */
#define MAX_LIFECYCLE_MAPS 64

static unsigned long pick_size(void)
{
	switch (rand() % 5) {
	case 0:	return page_size;
	case 1:	return page_size * (1 + (rand() % 16));
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
	return (int)mmap_prot_combos[effector_pick_array_index(EFFECTOR_NR(__NR_mmap), 2,
			mmap_prot_combos, ARRAY_SIZE(mmap_prot_combos))];
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
		free(obj);
		return true;	/* non-fatal */
	}
	obj->map.size = size;
	obj->map.prot = prot;
	obj->map.fd = -1;
	obj->map.type = CHILD_ANON;
	add_object(obj, OBJ_LOCAL, OBJ_MMAP_ANON);

	return true;
}

static bool do_mremap(void)
{
	struct object *obj;
	struct map *map;
	unsigned long new_size;
	void *p;

	obj = get_random_object(OBJ_MMAP_ANON, OBJ_LOCAL);
	if (obj == NULL)
		return true;

	map = &obj->map;

	/* Don't mremap initial mappings shared with siblings. */
	if (map->type == INITIAL_ANON)
		return true;

	if (range_overlaps_shared((unsigned long)map->ptr, map->size))
		return true;

	/* Grow or shrink. */
	if (RAND_BOOL())
		new_size = map->size + page_size * (1 + (rand() % 16));
	else
		new_size = max((unsigned long)page_size, map->size / 2) & PAGE_MASK;

	if (new_size == 0)
		new_size = page_size;

	p = mremap(map->ptr, map->size, new_size, MREMAP_MAYMOVE);
	if (p == MAP_FAILED)
		return true;

	map->ptr = p;
	map->size = new_size;
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

	(void)child;

	head = get_objhead(OBJ_LOCAL, OBJ_MMAP_ANON);
	nr_maps = head->num_entries;

	/*
	 * Bias toward creation when we have few maps,
	 * toward teardown when we have many.
	 */
	if (nr_maps < 4) {
		do_create();
	} else if (nr_maps >= MAX_LIFECYCLE_MAPS) {
		do_teardown();
	} else {
		switch (rand() % 10) {
		case 0 ... 3:	do_create();	break;
		case 4 ... 5:	do_mremap();	break;
		case 6 ... 7:	do_dirty();	break;
		case 8 ... 9:	do_teardown();	break;
		}
	}

	return true;
}
