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

/* Walk a list, get a random element */
static struct map * __get_map(struct list_head *head, unsigned int max)
{
	struct list_head *node;

	unsigned int i, j = 0;

	i = rand() % max;

	list_for_each(node, head) {
		struct map *m;

		m = (struct map *) node;

		if (i == j)
			return m;
		j++;
	}
	return NULL;
}

/* Return a pointer a previous mmap() that we did, either during startup,
 * or from a fuzz result. */
struct map * get_map(void)
{
	struct map *map;

	map = __get_map(&this_child->mappings->list, this_child->num_mappings);
	return map;
}
       #include <sys/types.h>
       #include <unistd.h>


/*
 * Set up a childs local mapping list.
 * A child inherits the global mappings, and will add to them
 * when it successfully completes mmap() calls.
 */
void init_child_mappings(struct childdata *child)
{
	struct list_head *node;

	child->mappings = zmalloc(sizeof(struct map));
	INIT_LIST_HEAD(&child->mappings->list);

	/* Copy the global mapping list to the child.
	 * Note we're only copying pointers here, the actual mmaps
	 * will be faulted into the child when they get accessed.
	 */
	list_for_each(node, &shared_mappings->list) {
		struct map *m, *new;

		m = (struct map *) node;

		new = zmalloc(sizeof(struct map));
		new->ptr = m->ptr;
		new->name = strdup(m->name);
		new->size = m->size;
		new->prot = m->prot;
		new->type = TRINITY_MAP_LOCAL;

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
