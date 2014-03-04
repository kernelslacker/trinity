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
#include "trinity.h"	// page_size

/* Walk the list, get the j'th element */
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

struct map * get_map(void)
{
	struct map *map;
	bool local = FALSE;

	/* If we're not running in child context, just do shared mappings. */
	if (this_child == 0)
		return __get_map(&shared_mappings->list, num_shared_mappings);

	/* Only toss the dice if we actually have local mappings. */
	if (shm->num_mappings[this_child] > 0)
		local = rand_bool();

	if (local == TRUE)
		map = __get_map(&shm->mappings[this_child]->list, shm->num_mappings[this_child]);
	else
		map = __get_map(&shared_mappings->list, num_shared_mappings);

	return map;
}

static void delete_local_mapping(int childno, struct map *map)
{
	list_del(&map->list);
	shm->num_mappings[childno]--;
}

void delete_mapping(int childno, struct map *map)
{
	if (map->type == MAP_LOCAL)
		delete_local_mapping(childno, map);

	/* Right now, we don't want to delete MAP_GLOBAL mappings */
}

struct map * common_set_mmap_ptr_len(int childno)
{
	struct map *map;

	map = (struct map *) shm->a1[childno];
	shm->scratch[childno] = (unsigned long) map;    /* Save this for ->post */
	if (map == NULL) {
		shm->a1[childno] = 0;
		shm->a2[childno] = 0;
		return NULL;
	}

	shm->a1[childno] = (unsigned long) map->ptr;
	shm->a2[childno] = map->size;           //TODO: Munge this.

	return map;
}

void dirty_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;
	unsigned int num_pages = map->size / page_size;

	/* Check mapping is writable. */
	if (!(map->prot & PROT_WRITE))
		return;

	switch (rand() % 6) {
	case 0:
		/* Just fault in one page. */
		p[rand() % map->size] = rand();
		break;

	case 1:
		/* fault in the whole mapping. */
		for (i = 0; i < map->size; i += page_size)
			p[i] = rand();
		break;

	case 2:
		/* every other page. */
		for (i = 0; i < map->size; i += (page_size * 2))
			p[i] = rand();
		break;

	case 3:
		/* whole mapping in reverse */
		for (i = (map->size - page_size); i > 0; i -= page_size)
			p[i] = rand();
		break;

	case 4:
		/* fault in map->size pages. (some may be faulted >once) */
		for (i = 0; i < num_pages; i++)
			p[rand() % (num_pages + 1)] = rand();
		break;

	case 5:
		/* fault in the last page in a mapping
		 * Fill it with ascii, in the hope we do something like
		 * a strlen and go off the end. */
		memset((void *) p + (map->size - page_size), 'A', page_size);
		break;
	}
}
