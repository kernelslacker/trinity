#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "arch.h"
#include "list.h"
#include "child.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "utils.h"

/*
 * Return a pointer a previous mmap() that we did, either during startup,
 * or from a fuzz result.
 */
struct map * get_map(void)
{
	struct object *obj;
	struct map *map;
	struct childdata *child = this_child();
	bool global;

	/*
	 * Some of the fd providers need weird mappings on startup.
	 * (fd-perf for eg), these are called from the main process,
	 * and hence don't have a valid this_child, so we address the
	 * initial mappings list directly.
	 */
	if (child == NULL)
		global = OBJ_GLOBAL;
	else
		global = OBJ_LOCAL;

	obj = get_random_object(OBJ_MMAP, global);
	map = &obj->map;

	return map;
}

void map_destructor(struct object *obj)
{
	struct map *map;

	map = &obj->map;
	munmap(map->ptr, map->size);
	free(map->name);
}

/*
 * Set up a childs local mapping list.
 * A child inherits the initial mappings, and will add to them
 * when it successfully completes mmap() calls.
 */
void init_child_mappings(void)
{
	struct list_head *globallist, *node;
	struct objhead *head;
	struct childdata *child = this_child();

	init_object_lists(OBJ_LOCAL);

	head = &child->objects[OBJ_MMAP];
	head->destroy = &map_destructor;

	globallist = shm->global_objects[OBJ_MMAP].list;

	/* Copy the initial mapping list to the child.
	 * Note we're only copying pointers here, the actual mmaps
	 * will be faulted into the child when they get accessed.
	 */
	list_for_each(node, globallist) {
		struct map *m;
		struct object *globalobj, *newobj;

		globalobj = (struct object *) node;
		m = &globalobj->map;

		newobj = alloc_object();
		newobj->map.ptr = m->ptr;
		newobj->map.name = strdup(m->name);
		newobj->map.size = m->size;
		newobj->map.prot = m->prot;
		/* We leave type as 'INITIAL' until we change the mapping
		 * by mprotect/mremap/munmap etc..
		 */
		newobj->map.type = TRINITY_MAP_INITIAL;
		add_object(newobj, OBJ_LOCAL, OBJ_MMAP);
	}
}

/* used in several sanitise_* functions. */
struct map * common_set_mmap_ptr_len(void)
{
	struct syscallrecord *rec;
	struct map *map;
	struct childdata *child = this_child();

	rec = &child->syscall;
	map = (struct map *) rec->a1;
	if (map == NULL) {
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	rec->a1 = (unsigned long) map->ptr;
	rec->a2 = rnd() % map->size;
	rec->a2 &= PAGE_MASK;

	return map;
}

/*
 * Routine to perform various kinds of write operations to a mapping
 * that we created.
 */
void dirty_mapping(struct map *map)
{
	bool rw = RAND_BOOL();

	if (rw == TRUE) {
		/* Check mapping is writable, or we'll segv.
		 * TODO: Perhaps we should do that, and trap it, mark it writable,
		 * then reprotect after we dirtied it ? */
		if (map->prot & ~PROT_WRITE)
			return;

		random_map_writefn(map);
		return;

	} else {
		if (map->prot & ~PROT_READ)
			return;

		random_map_readfn(map);
	}
}

/*
 * Pick a random mapping, and perform some r/w op on it.
 * Called from child on child init, and also periodically
 * from periodic_work()
 */
void dirty_random_mapping(void)
{
	struct map *map;

	map = get_map();
	dirty_mapping(map);
}
