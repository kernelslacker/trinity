#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "trinity.h"
#include "arch.h"

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

	if (quiet_level == 0)
		output("There are %d entries in the map table\n", num_mappings);

	for (j = 0; j < num_mappings; j++) {
		if (quiet_level == 0)
			output(" start: %p  name: %s\n", tmpmap->ptr, tmpmap->name);
		tmpmap = tmpmap->next;
	}
}

void * alloc_zero_map(struct map *map, int prot, const char *name)
{
	struct map *tmpmap = map;
	int fd;

	if (!tmpmap)
		tmpmap = alloc_map();

	fd = open("/dev/zero", O_RDWR);
	if (!fd) {
		printf("open /dev/zero failure\n");
		exit(EXIT_FAILURE);
	}

	/* page_size * 2, so we have a guard page afterwards.
	 * This is necessary for when we want to test page boundaries.
	 * see end of _get_address() for details.
	 */
	tmpmap->ptr = mmap(NULL, page_size * 2, prot, MAP_PRIVATE, fd, 0);


	if (!tmpmap->ptr) {
		printf("mmap /dev/zero failure\n");
		exit(EXIT_FAILURE);
	}
	tmpmap->name = malloc(80);
	sprintf(tmpmap->name, "/dev/zero(%s)", name);
	num_mappings++;

	if (quiet_level == 0)
		output("mapping[%d]: (zeropage %s) %p\n", num_mappings - 1, name, tmpmap->ptr);

	close(fd);
	return tmpmap;
}


void setup_maps()
{
	struct map *tmpmap;
	unsigned int fd, i;

	tmpmap = maps_list = alloc_map();

	/* Make sure our zero page mappings are nowhere near the shm. */
	fd = open("/dev/zero", O_RDWR);
	for (i = 0; i < 50; i++)
		mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	/* Add a bunch of /dev/zero mappings */
	tmpmap->next = alloc_zero_map(tmpmap, PROT_READ | PROT_WRITE, "PROT_READ | PROT_WRITE");
	tmpmap = tmpmap->next;

	tmpmap->next = alloc_zero_map(NULL, PROT_READ, "PROT_READ");
	tmpmap = tmpmap->next;

	tmpmap->next = alloc_zero_map(NULL, PROT_WRITE, "PROT_WRITE");
	tmpmap = tmpmap->next;

	if (quiet_level == 0)
		output("Added /dev/zero mappings.\n");
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

void destroy_maps()
{
	unsigned int i;
	struct map *thismap = maps_list, *next;

	for (i = 0; i < num_mappings; i++) {
		next = thismap->next;
		free(thismap->name);
		free(thismap);
		thismap = next;
	}
	num_mappings = 0;
}
