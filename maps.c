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
	struct list_head *node, *list;
	unsigned int num;

	unsigned int i, j = 0;

	/*
	 * Some of the fd providers need weird mappings on startup.
	 * (fd-perf for eg), these are called from the main process,
	 * and hence don't have a valid this_child, so we address the
	 * initial mappings list directly.
	 */
	if (this_child == NULL) {
		list = &initial_mappings->list;
		num = num_initial_mappings;
	} else {
		list = &this_child->mappings->list;
		num = this_child->num_mappings;
	}

	i = rand() % num;

	list_for_each(node, list) {
		struct map *m;

		m = (struct map *) node;

		if (i == j)
			return m;
		j++;
	}
	return NULL;
}

/*
 * Set up a childs local mapping list.
 * A child inherits the initial mappings, and will add to them
 * when it successfully completes mmap() calls.
 */
void init_child_mappings(struct childdata *child)
{
	struct list_head *node;

	child->mappings = zmalloc(sizeof(struct map));
	INIT_LIST_HEAD(&child->mappings->list);

	/* Copy the initial mapping list to the child.
	 * Note we're only copying pointers here, the actual mmaps
	 * will be faulted into the child when they get accessed.
	 */
	list_for_each(node, &initial_mappings->list) {
		struct map *m, *new;

		m = (struct map *) node;

		new = zmalloc(sizeof(struct map));
		new->ptr = m->ptr;
		new->name = strdup(m->name);
		new->size = m->size;
		new->prot = m->prot;
		/* We leave type as 'INITIAL' until we change the mapping
		 * by mprotect/mremap/munmap etc..
		 */
		new->type = TRINITY_MAP_INITIAL;

		list_add_tail(&new->list, &this_child->mappings->list);
		this_child->num_mappings++;
	}
}

/* Called from munmap()'s ->post routine. */
void delete_mapping(struct map *map)
{
	list_del(&map->list);
	this_child->num_mappings--;
}

/* used in several sanitise_* functions. */
struct map * common_set_mmap_ptr_len(void)
{
	struct syscallrecord *rec;
	struct map *map;

	rec = &this_child->syscall;
	map = (struct map *) rec->a1;
	if (map == NULL) {
		rec->a1 = 0;
		rec->a2 = 0;
		return NULL;
	}

	rec->a1 = (unsigned long) map->ptr;
	rec->a2 = rand() % map->size;
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
		if (!(map->prot & PROT_WRITE))
			return;

		random_map_writefn(map);
		return;

	} else {
		if (!(map->prot & PROT_READ))
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
