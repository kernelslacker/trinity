/*
 * Routines to dirty/fault-in mapped pages.
 */

#include <sys/mman.h>
#include "maps.h"
#include "random.h"

/*
 * Routine to perform various kinds of write operations to a mapping
 * that we created.
 */
void dirty_mapping(struct map *map)
{
	bool rw = rand_bool();

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

void dirty_random_mapping(void)
{
	struct map *map;

	map = get_map();
	dirty_mapping(map);
}
