#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "arch.h"
#include "maps.h"
#include "random.h"

/*
 * Routine to perform various kinds of write operations to a mapping
 * that we created.
 */
void dirty_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;
	unsigned int num_pages = map->size / page_size;

	/* Check mapping is writable, or we'll segv.
	 * TODO: Perhaps we should do that, and trap it, mark it writable,
	 * then reprotect after we dirtied it ? */
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
		/* fault in a random set of map->size pages. (some may be faulted >once) */
		for (i = 0; i < num_pages; i++)
			p[(rand() % (num_pages + 1)) * page_size] = rand();
		break;

	case 5:
		/* fault in the last page in a mapping
		 * Fill it with ascii, in the hope we do something like
		 * a strlen and go off the end. */
		memset((void *) p + (map->size - page_size), 'A', page_size);
		break;
	}
}
