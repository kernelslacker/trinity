#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "trinity.h"

static unsigned int num_mappings = 0;

static struct map *maps_list;

static struct map * alloc_map()
{
	struct map *newmap;

	newmap = malloc(sizeof(struct map));
	if (!newmap) {
		printf("Couldn't allocate maps list!\n");
		exit(EXIT_FAILURE);
	}
	memset(newmap, 0, sizeof(struct map));
	return newmap;
}

static void dump_maps()
{
	struct map *tmpmap = maps_list;
	unsigned int j;

	printf("There are %d entries in the map table\n", num_mappings);

	for (j = 0; j < num_mappings; j++) {
		printf(" start: %p\n", tmpmap->ptr);
		tmpmap = tmpmap->next;
	}
}

void setup_maps()
{
	FILE *f;
	void *startaddr, *endaddr;
	struct map *tmpmap;

	f = fopen("/proc/self/maps", "r");
	if (!f) {
		printf("Couldn't open /proc/self/maps!\n");
		exit(EXIT_FAILURE);
	}

	tmpmap = maps_list = alloc_map();
	do {
		fscanf(f, "%p-%p %*[^\n]\n", &startaddr, &endaddr);

		/* skip over the shm, in case we corrupt it*/
		if (startaddr == shm)
			continue;

		tmpmap->ptr = startaddr;
		num_mappings++;

		tmpmap->next = alloc_map();
		tmpmap = tmpmap->next;

	} while (!feof(f));

	/* free the empty map on the end */
	free(tmpmap);

	printf("Added %d mappings\n", num_mappings);

	dump_maps();
}

void * get_map()
{
	struct map *tmpmap = maps_list;
	unsigned int i, j;

	i = rand() % num_mappings;
	for (j = 0; j < i; j++)
		tmpmap = tmpmap->next;

	return tmpmap->ptr;
}
