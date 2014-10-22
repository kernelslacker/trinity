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
	bool local = FALSE;

	/* If we're not running in child context, just do shared mappings.
	 * because main doesn't have any 'local' mappings.
	 * FIXME: do we still need this? Are we still calling this from main
	 * since the removal of page_rand  ?
	 */
	if (this_child != NULL) {
		if (this_child->num_mappings > 0)
			local = rand_bool();
	}

	if (local == TRUE)
		map = __get_map(&this_child->mappings->list, this_child->num_mappings);
	else
		map = __get_map(&shared_mappings->list, num_shared_mappings);

	return map;
}

static void delete_local_mapping(struct map *map)
{
	list_del(&map->list);
	this_child->num_mappings--;
}

/* Called from munmap()'s ->post routine. */
void delete_mapping(struct map *map)
{
	if (map->type == TRINITY_MAP_LOCAL)
		delete_local_mapping(map);

	/* Right now, we don't want to delete TRINITY_MAP_GLOBAL mappings */
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
