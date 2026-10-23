/*
 * Self-check for the code that tells a child's arena-backed pool storage
 * from libc heap: get_random_object(), objpool_check() and for_each_obj
 * take arena, fallback and mixed pools and refuse storage in neither, and
 * clone_global_mmap_pool()'s dedup walk refreshes alloc_track only for a
 * fallback copy.  The heap probe answers for one buffer, so the arena
 * lies outside the heap as it does in a child.
 */

#include <stdbool.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "mm/maps-internal.h"	/* clone_global_mmap_pool */
#include "objects.h"
#include "objects-internal.h"	/* objpool_local_arena_alloc */
#include "shm.h"

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern unsigned long fake_heap_start, fake_heap_size;		/* fake_shm.c */

#define POOL_TYPE	OBJ_KEY_SERIAL
#define POOL_SIZE	4
#define DRAWS		256

static struct objhead pool;

static struct objhead *the_pool(enum obj_scope scope, enum objecttype type)
{
	if (scope == OBJ_LOCAL && type == POOL_TYPE)
		return &pool;
	return NULL;
}

/* All the heap probe accepts: storage the zmalloc_tracked() fallback hands out. */
static struct {
	struct object *array[POOL_SIZE];
	struct object objs[POOL_SIZE];
} heap_store;

/* In neither the arena nor the heap, where a scribbled pointer lands. */
static struct {
	struct object *array[POOL_SIZE];
	struct object objs[POOL_SIZE];
} stray_store;

static void *arena_alloc(unsigned long size)
{
	void *p = objpool_local_arena_alloc(size);

	if (p == NULL)
		BUG("objpool reader: the objpool arena could not be allocated from");
	return p;
}

static void fill_pool(struct object **array, struct object *const *objs,
		      unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		objs[i]->obj_type = POOL_TYPE;
		array[i] = objs[i];
	}
	pool.array = array;
	pool.num_entries = n;
	pool.array_capacity = n;
}

static bool in_pool(const struct object *obj)
{
	unsigned int i;

	for (i = 0; i < pool.num_entries; i++) {
		if (pool.array[i] == obj)
			return true;
	}
	return false;
}

/* Every reader takes every pooled object, and counts nothing as corrupt. */
static void readers_take_pool(void)
{
	unsigned long stale = shm->stats.diag.objpool_array_stale_caught;
	unsigned long uaf = shm->stats.diag.global_obj_uaf_caught;
	struct object *obj;
	unsigned int i, idx, walked = 0;

	for (i = 0; i < DRAWS; i++) {
		obj = get_random_object(POOL_TYPE, OBJ_LOCAL);
		if (obj == NULL || !in_pool(obj))
			BUG("objpool reader: get_random_object() did not draw from the pool");
	}
	for (i = 0; i < pool.num_entries; i++) {
		if (!objpool_check(pool.array[i], POOL_TYPE))
			BUG("objpool reader: objpool_check() refused a pooled object");
	}
	for_each_obj(&pool, obj, idx) {
		if (obj != pool.array[idx])
			BUG("objpool reader: for_each_obj yielded another slot");
		walked++;
	}
	if (walked != pool.num_entries)
		BUG("objpool reader: for_each_obj did not walk the whole pool");
	if (shm->stats.diag.objpool_array_stale_caught != stale ||
	    shm->stats.diag.global_obj_uaf_caught != uaf)
		BUG("objpool reader: a healthy pool was counted as corrupt");
}

/* Neither array reader loads from the pool's array, and each counts it. */
static void readers_refuse_array(void)
{
	unsigned long stale = shm->stats.diag.objpool_array_stale_caught;
	struct object *obj;
	unsigned int idx;

	if (get_random_object(POOL_TYPE, OBJ_LOCAL) != NULL)
		BUG("objpool reader: get_random_object() drew from a refused array");
	for_each_obj(&pool, obj, idx) {
		BUG("objpool reader: for_each_obj walked a refused array");
	}
	if (shm->stats.diag.objpool_array_stale_caught != stale + 2)
		BUG("objpool reader: a refused array was not counted");
}

static void check_refuses_obj(struct object *obj)
{
	unsigned long uaf = shm->stats.diag.global_obj_uaf_caught;

	if (objpool_check(obj, POOL_TYPE))
		BUG("objpool reader: objpool_check() took an object it should refuse");
	if (shm->stats.diag.global_obj_uaf_caught != uaf + 1)
		BUG("objpool reader: a refused object was not counted");
}

/* What alloc_object() and the grow path give a child: all arena storage. */
static void arena_pool_is_read(struct object **arena_objs)
{
	struct object **array = arena_alloc(POOL_SIZE * sizeof(*array));
	unsigned int i;

	for (i = 0; i < POOL_SIZE; i++)
		arena_objs[i] = arena_alloc(sizeof(struct object));
	fill_pool(array, arena_objs, POOL_SIZE);
	readers_take_pool();

	arena_objs[0]->obj_type = OBJ_PID;
	check_refuses_obj(arena_objs[0]);
	arena_objs[0]->obj_type = POOL_TYPE;
}

/* The zmalloc_tracked() fallback, and the two mixes a pool holds once the
 * arena runs out: an arena array of fallback objects, and a fallback
 * array, from a grow after that, of arena objects. */
static void fallback_pool_is_read(struct object **arena_objs)
{
	struct object *heap_objs[POOL_SIZE];
	unsigned int i;

	for (i = 0; i < POOL_SIZE; i++)
		heap_objs[i] = &heap_store.objs[i];
	fill_pool(heap_store.array, heap_objs, POOL_SIZE);
	readers_take_pool();

	fill_pool(arena_alloc(POOL_SIZE * sizeof(struct object *)), heap_objs,
		  POOL_SIZE);
	readers_take_pool();

	fill_pool(heap_store.array, arena_objs, POOL_SIZE);
	readers_take_pool();
}

/* A scribbled array or object pointer is refused before the load. */
static void stray_storage_is_refused(void)
{
	struct object *stray_objs[POOL_SIZE];
	unsigned int i;

	for (i = 0; i < POOL_SIZE; i++)
		stray_objs[i] = &stray_store.objs[i];
	fill_pool(stray_store.array, stray_objs, POOL_SIZE);
	readers_refuse_array();

	for (i = 0; i < POOL_SIZE; i++)
		check_refuses_obj(stray_objs[i]);
}

static struct objhead global_maps, local_maps;

static struct objhead *the_map_pools(enum obj_scope scope,
				     enum objecttype type)
{
	if (type != OBJ_MMAP_ANON)
		return NULL;
	return scope == OBJ_GLOBAL ? &global_maps : &local_maps;
}

/*
 * The dedup walk refreshes the alloc_track slot of a local copy only when
 * it is a libc-fallback object, which release_obj() will hand to
 * deferred_free_enqueue(); an arena copy is never tracked.  Every global
 * map here already has a local copy, so the walk clones nothing, and the
 * fallback copy is not tracked either, so its refresh is the one consume
 * miss the walk may count.  The regions alloc_track_refresh() reads are
 * the ones deferred_free_ownership_self_check() set up.
 */
static void dedup_refreshes_only_fallback_copies(void)
{
	static char name[] = "dedup";
	static struct object global_objs[POOL_SIZE];
	struct object **local_array = arena_alloc(POOL_SIZE * sizeof(*local_array));
	unsigned long miss = shm->stats.deferred_free.alloc_track_refresh_consume_miss;
	unsigned long refreshed;
	unsigned int i;

	for (i = 0; i < POOL_SIZE; i++) {
		struct object *copy = i == 0 ? &heap_store.objs[0]
					     : arena_alloc(sizeof(struct object));

		global_objs[i].map.name = name;
		global_objs[i].map.ptr = (void *)(0x10000UL * (i + 1));
		heap_store.array[i] = &global_objs[i];
		copy->map.ptr = global_objs[i].map.ptr;
		local_array[i] = copy;
	}
	global_maps = (struct objhead){ .array = heap_store.array,
					.num_entries = POOL_SIZE };
	local_maps = (struct objhead){ .array = local_array,
				       .num_entries = POOL_SIZE };

	fake_get_objhead = the_map_pools;
	clone_global_mmap_pool(OBJ_MMAP_ANON);
	fake_get_objhead = the_pool;

	refreshed = shm->stats.deferred_free.alloc_track_refresh_consume_miss - miss;
	if (refreshed > 1)
		BUG("objpool reader: the dedup walk refreshed an arena copy");
	if (refreshed == 0)
		BUG("objpool reader: the dedup walk did not refresh the fallback copy");
}

/* Take what is left of the arena, largest block first.  Every block is a
 * multiple of 16 bytes, so the last one ends where the arena does. */
static unsigned long take_rest_of_arena(void)
{
	unsigned long size, end = 0;
	void *p;

	for (size = 1UL << 30; size >= 16; size >>= 1) {
		while ((p = objpool_local_arena_alloc(size)) != NULL)
			end = (unsigned long)p + size;
	}
	if (end == 0)
		BUG("objpool reader: the objpool arena had no room left");
	return end;
}

/*
 * The arena has to hold all a reader loads, not just where it starts.  An
 * array in the arena's last slot holds one entry and not two; an object
 * ending at the arena's end is taken, one 8 bytes on is not, though the
 * type it would read matches.  The arena alone judges an address inside
 * it, so a heap probe that knows no allocator region, and accepts
 * anything, does not change the answer.
 */
static void arena_extent_is_checked(struct object *arena_obj)
{
	unsigned long end = take_rest_of_arena();
	struct object **tail = (struct object **)(end - sizeof(struct object *));
	struct object *last = (struct object *)(end - sizeof(struct object));
	struct object *crossing = (struct object *)((unsigned long)last + 8);
	unsigned long heap_size = fake_heap_size;

	fill_pool(tail, &arena_obj, 1);
	readers_take_pool();

	memset(last, 0, sizeof(*last));
	last->obj_type = POOL_TYPE;
	crossing->obj_type = POOL_TYPE;
	if (!objpool_check(last, POOL_TYPE))
		BUG("objpool reader: objpool_check() refused the arena's last object");

	pool.num_entries = 2;
	check_refuses_obj(crossing);
	readers_refuse_array();
	fake_heap_size = 0;
	check_refuses_obj(crossing);
	readers_refuse_array();
	fake_heap_size = heap_size;
}

void objpool_reader_self_check(void);
void objpool_reader_self_check(void)
{
	struct object *arena_objs[POOL_SIZE];

	objpool_local_arena_init();
	fake_heap_start = (unsigned long)&heap_store;
	fake_heap_size = sizeof(heap_store);
	fake_get_objhead = the_pool;

	arena_pool_is_read(arena_objs);
	fallback_pool_is_read(arena_objs);
	stray_storage_is_refused();
	dedup_refreshes_only_fallback_copies();
	arena_extent_is_checked(arena_objs[0]);

	fake_get_objhead = NULL;
	fake_heap_size = 0;
	memset(&pool, 0, sizeof(pool));
}
