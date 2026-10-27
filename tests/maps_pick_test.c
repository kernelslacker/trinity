/*
 * Self-check for get_map_handle()'s pick for a compat call, whose kernel
 * reads an address slot as its low 32 bits: it is handed a mapping that
 * lies wholly below 4 GiB whenever the pool holds one, and another only
 * when the pool holds none, while a native call draws from them all.
 */

#include <stdbool.h>
#include <string.h>

#include "arch.h"		/* page_size */
#include "child.h"
#include "debug.h"		/* BUG */
#include "maps.h"
#include "objects.h"

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern unsigned long fake_heap_start, fake_heap_size;		/* fake_shm.c */
extern struct childdata *fake_this_child;			/* fake_shm.c */

#define HIGH_MAP	0x7e0000000000UL
#define LOW_MAP		0x40000000UL
/* Starts below 4 GiB and ends past it. */
#define STRADDLE_MAP	((1UL << 32) - 4 * 4096UL)
#define DRAWS		256

static struct objhead anon_pool;
static struct childdata child;

/* The heap probe takes this, so the pool readers accept it as storage. */
static struct {
	struct object *array[2];
	struct object objs[2];
} store;

static struct objhead *the_anon_pool(enum obj_scope scope,
				     enum objecttype type)
{
	if (scope == OBJ_LOCAL && type == OBJ_MMAP_ANON)
		return &anon_pool;
	return NULL;
}

/* A pool of two 16-page mappings, at @a and @b. */
static void fill_anon_pool(unsigned long a, unsigned long b)
{
	unsigned long ptrs[2] = { a, b };
	unsigned int i;

	memset(&store, 0, sizeof(store));
	for (i = 0; i < 2; i++) {
		store.objs[i].obj_type = OBJ_MMAP_ANON;
		store.objs[i].map.ptr = (void *) ptrs[i];
		store.objs[i].map.size = 16 * page_size;
		store.array[i] = &store.objs[i];
	}
	anon_pool.array = store.array;
	anon_pool.num_entries = 2;
	anon_pool.array_capacity = 2;
}

/* Which of the pool's mappings DRAWS picks handed out, as bits. */
static unsigned int maps_drawn(bool compat)
{
	unsigned int i, seen = 0;

	child.syscall.do32bit = compat;
	for (i = 0; i < DRAWS; i++) {
		struct map_handle h;

		if (!get_map_handle(&h))
			BUG("maps pick: a pool with mappings handed out none");
		if (h.map == &store.objs[0].map)
			seen |= 1;
		else if (h.map == &store.objs[1].map)
			seen |= 2;
		else
			BUG("maps pick: a mapping from outside the pool was handed out");
	}
	return seen;
}

void maps_pick_self_check(void);
void maps_pick_self_check(void)
{
	fake_heap_start = (unsigned long) &store;
	fake_heap_size = sizeof(store);
	fake_get_objhead = the_anon_pool;
	child.mmap_pool_nonempty_mask = 1u << 0;	/* the ANON pool */
	fake_this_child = &child;

	fill_anon_pool(HIGH_MAP, LOW_MAP);
	if (maps_drawn(true) != 2)
		BUG("maps pick: a compat call was handed a mapping past 4 GiB with one below in the pool");
	if (maps_drawn(false) != 3)
		BUG("maps pick: a native call did not draw from every mapping");

	fill_anon_pool(STRADDLE_MAP, LOW_MAP);
	if (maps_drawn(true) != 2)
		BUG("maps pick: a compat call was handed a mapping that runs past 4 GiB");

	fill_anon_pool(HIGH_MAP, HIGH_MAP + MB(1));
	if (maps_drawn(true) != 3)
		BUG("maps pick: a compat call with no mapping below 4 GiB was not handed the others");

	fake_this_child = NULL;
	fake_get_objhead = NULL;
	fake_heap_size = 0;
}
