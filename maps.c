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

	output("There are %d entries in the map table\n", num_mappings);

	for (j = 0; j < num_mappings; j++) {
		output(" start: %p  name: %s\n", tmpmap->ptr, tmpmap->name);
		tmpmap = tmpmap->next;
	}
}

void * alloc_zero_map(struct map *map, int prot, char *name)
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
	tmpmap->ptr = mmap(NULL, page_size, prot, MAP_PRIVATE, fd, 0);

	if (!tmpmap->ptr) {
		printf("mmap /dev/zero failure\n");
		exit(EXIT_FAILURE);
	}
	tmpmap->name = malloc(80);
	sprintf(tmpmap->name, "/dev/zero(%s)", name);
	num_mappings++;

	output("mapping[%d]: (zeropage %s) %p\n", num_mappings - 1, name, tmpmap->ptr);

	close(fd);
	return tmpmap;
}


void setup_maps()
{
	FILE *f;
	void *startaddr, *endaddr;
	struct map *tmpmap;
	unsigned int ret, fd, i;
	char name[80];
	char ch;

	f = fopen("/proc/self/maps", "r");
	if (!f) {
		printf("Couldn't open /proc/self/maps!\n");
		exit(EXIT_FAILURE);
	}

	tmpmap = maps_list = alloc_map();
	do {
		ret = fscanf(f, "%p-%p", &startaddr, &endaddr);
		if (ret == 0) {
			printf("/proc/maps parsing failure\n");
			exit(EXIT_FAILURE);
		}

		/* skip over the shm (and any nearby mappings), in case we corrupt it*/
		if ((startaddr > (void *) shm - (page_size * 8)) &&
		    (startaddr < (void *) shm + (page_size * 8))) {
			output("skipping mapping at %p -> %p (too close to shm at %p)\n", startaddr, endaddr, shm);
			do {
				ch = getc(f);
			} while ((ch != EOF) && (ch != '\n'));
			continue;
		}

		// search forward until we reach a name or eol
		do {
			ch = getc(f);
		} while ((ch != EOF) && (ch != '\n') && (ch != '/') && (ch != '['));

		if (ch == EOF)
			break;

		// Store the name if we find it.
		if ((ch == '/') || (ch == '[')) {
			ungetc(ch, f);
			if (fgets(name, 80, f) == NULL)
				break;
			name[strlen(name) - 1] = '\0';
			tmpmap->name = strdup(name);
		}

		tmpmap->ptr = startaddr;
		num_mappings++;

		tmpmap->next = alloc_map();

		output("mapping[%d]: %p-%p ", num_mappings - 1, startaddr, endaddr);
		if (tmpmap->name)
			output("%s", tmpmap->name);
		output("\n");

		tmpmap = tmpmap->next;

	} while (!feof(f));

	fclose(f);
	output("Added %d mappings from /proc/self\n", num_mappings);

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
