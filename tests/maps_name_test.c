/*
 * Self-check for the names of a child's local map pool entries.  They
 * borrow a name, the string of the global entry they were cloned from, so
 * map_destructor() (mm/maps-lifecycle.c, linked as a parent TU) only clears
 * the pointer.  init_child_mappings() runs over fake pools, with
 * alloc_object() and add_object() hooked.
 * Entry point: maps_name_self_check().
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "child-api.h"		/* init_child_mappings */
#include "debug.h"		/* BUG */
#include "deferred-free.h"
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "maps.h"
#include "objects.h"
#include "shm.h"

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

/*
 * Run the OBJ_LOCAL destructor on a pool entry whose only live field is the
 * name.  owns_vma stays false, as for a borrowed clone, so no munmap runs.
 */
static void destroy_with_name(char *name)
{
	struct object obj;

	memset(&obj, 0, sizeof(obj));
	obj.map.name = name;
	map_destructor(&obj);
	if (obj.map.name != NULL)
		BUG("map name: map_destructor() left the name pointer set");
}

/*
 * A name is borrowed from its owner, which has not released it yet: even a
 * live allocation the alloc_track vouches for is neither consumed nor freed.
 */
static void destructor_leaves_a_tracked_name_to_its_owner(void)
{
	char *owned = calloc(1, 8);

	if (owned == NULL)
		BUG("map name: out of memory");
	memcpy(owned, "owner", 6);
	deferred_alloc_track(owned, 8);

	destroy_with_name(owned);
	if (!alloc_track_lookup(owned))
		BUG("map name: map_destructor() consumed the tracker entry of a borrowed name");
	if (strcmp(owned, "owner") != 0)
		BUG("map name: map_destructor() freed a borrowed name");
	tracked_free_now(owned);
}

/* Unhooked, alloc_object() is the real one: a zeroed object off the heap. */
static void alloc_object_defaults_to_the_real_one(void)
{
	struct object *obj = alloc_object();

	if (obj == NULL || obj->obj_type != OBJ_NONE)
		BUG("map name: unhooked alloc_object() did not reach the real one");
	free(obj);
}

/*
 * Fake pools: ANON, which init_child_mappings() seeds in its own loop, and
 * FILE, which it seeds through clone_global_mmap_pool(); each global one
 * holds one entry to clone.  The TESTFILE pools are absent, which both
 * paths tolerate.  Indexed [scope][pool], the scope enum first, the pool as
 * mmap_pool_bit_for_type() numbers it.
 */
#define NR_POOLS	2
#define POOL_CAP	2

static char anon_name[] = "anon(PROT_READ)";
static char file_name[] = "/proc/self/exe";
static char *const global_name[NR_POOLS] = { anon_name, file_name };

static struct objhead heads[2][NR_POOLS];
static struct object *arrays[2][NR_POOLS][POOL_CAP];
static struct object globals[NR_POOLS];
static struct objhead *(*saved_hook)(enum obj_scope scope, enum objecttype type);

static struct objhead *pool_head(enum obj_scope scope, enum objecttype type)
{
	int pool = mmap_pool_bit_for_type(type);

	if (pool < 0 || pool >= NR_POOLS)
		return NULL;
	return &heads[scope][pool];
}

/* What alloc_object() hands a process outside the objpool arena. */
static struct object *pool_alloc_object(void)
{
	struct object *obj = calloc(1, sizeof(*obj));

	if (obj == NULL)
		BUG("map name: out of memory");
	return obj;
}

static void pool_add_object(struct object *obj, enum obj_scope scope,
			    enum objecttype type)
{
	struct objhead *head = pool_head(scope, type);

	if (head == NULL || head->num_entries == POOL_CAP)
		BUG("map name: a clone was added to no pool, or to a full one");
	obj->obj_type = type;
	head->array[head->num_entries++] = obj;
}

static void pools_arm(void)
{
	unsigned int pool;

	memset(heads, 0, sizeof(heads));
	for (pool = 0; pool < NR_POOLS; pool++) {
		struct map *m = &globals[pool].map;

		heads[OBJ_LOCAL][pool].array = arrays[OBJ_LOCAL][pool];
		heads[OBJ_GLOBAL][pool].array = arrays[OBJ_GLOBAL][pool];

		memset(&globals[pool], 0, sizeof(globals[pool]));
		globals[pool].obj_type = pool == 0 ? OBJ_MMAP_ANON : OBJ_MMAP_FILE;
		m->ptr = (void *)(uintptr_t)(0x7f1000000000UL + pool * 0x10000UL);
		m->name = global_name[pool];
		m->size = m->tracked_size = 0x10000;
		m->prot = PROT_READ;
		m->type = pool == 0 ? INITIAL_ANON : MMAPED_FILE;
		m->owns_vma = true;
		arrays[OBJ_GLOBAL][pool][0] = &globals[pool];
		heads[OBJ_GLOBAL][pool].num_entries = 1;
	}
	saved_hook = fake_get_objhead;
	fake_get_objhead = pool_head;
	fake_alloc_object = pool_alloc_object;
	fake_add_object = pool_add_object;
}

/* Each clone points at its global entry's string, not at a copy of it. */
static void clones_borrow_the_global_name(void)
{
	unsigned int pool;

	init_child_mappings();
	for (pool = 0; pool < NR_POOLS; pool++) {
		struct objhead *head = &heads[OBJ_LOCAL][pool];

		if (head->num_entries != 1)
			BUG("map name: a local pool did not take its clone");
		if (head->array[0]->map.name != global_name[pool])
			BUG("map name: a clone does not borrow its global entry's name");
	}
}

/*
 * What __destroy_object() does to each entry: the head's destructor, then
 * the release of the object.  Nothing is freed or counted as a reject, and
 * the global strings are left as they were.
 */
static void destroying_a_clone_leaves_the_name_alone(void)
{
	unsigned long before = shm->stats.deferred_free.reject_untracked;
	unsigned int pool;

	for (pool = 0; pool < NR_POOLS; pool++) {
		struct objhead *head = &heads[OBJ_LOCAL][pool];
		struct object *obj = head->array[0];

		if (head->destroy != map_destructor)
			BUG("map name: a local pool does not use map_destructor()");
		head->destroy(obj);
		if (obj->map.name != NULL)
			BUG("map name: the destructor left a clone's name set");
		free(obj);
		head->array[0] = NULL;
		head->num_entries = 0;
	}

	if (shm->stats.deferred_free.reject_untracked != before)
		BUG("map name: destroying a clone went through the tracker");
	if (strcmp(anon_name, "anon(PROT_READ)") != 0 ||
	    strcmp(file_name, "/proc/self/exe") != 0)
		BUG("map name: destroying a clone touched a global name");
}

void maps_name_self_check(void);
void maps_name_self_check(void)
{
	destructor_leaves_a_tracked_name_to_its_owner();
	alloc_object_defaults_to_the_real_one();

	pools_arm();
	clones_borrow_the_global_name();
	destroying_a_clone_leaves_the_name_alone();
	fake_get_objhead = saved_hook;
	fake_alloc_object = NULL;
	fake_add_object = NULL;
}
