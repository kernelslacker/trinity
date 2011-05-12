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
	unsigned int ret;
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

		/* skip over the shm, in case we corrupt it*/
		if (startaddr == shm) {
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
