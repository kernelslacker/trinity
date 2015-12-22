/*
 * These routines create initial mmaps in the main process that every
 * child process will end up inheriting.
 *
 * Children will copy the whole initial_mappings list to their own
 * private copies, and then perform operations upon them.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "arch.h"
#include "list.h"
#include "log.h"
#include "maps.h"
#include "utils.h"

static void dump_initial_mappings(void)
{
	struct list_head *node, *list;
	struct objhead *head;

	head = &shm->global_objects[OBJ_MMAP];
	list = head->list;

	output(2, "There are %d entries in the map table\n", head->num_entries);

	list_for_each(node, list) {
		struct object *obj;
		struct map *m;
		char buf[11];

		obj = (struct object *) node;
		m = &obj->map;
		sizeunit(m->size, buf);
		output(2, " start: %p size:%s  name: %s\n", m->ptr, buf, m->name);
	}
}

static void alloc_zero_map(unsigned long size, int prot, const char *name)
{
	struct object *new;
	int fd;

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		outputerr("couldn't open /dev/zero\n");
		exit(EXIT_FAILURE);
	}

	new = alloc_object();
	new->map.size = size;
	new->map.prot = prot;
	new->map.type = TRINITY_MAP_INITIAL;
	new->map.ptr = mmap(NULL, size, prot, MAP_ANONYMOUS | MAP_SHARED, fd, 0);
	if (new->map.ptr == MAP_FAILED) {
		outputerr("mmap failure\n");
		exit(EXIT_FAILURE);
	}

	new->map.name = zmalloc(80);

	sprintf(new->map.name, "anon(%s)", name);

	add_object(new, OBJ_GLOBAL, OBJ_MMAP);

	close(fd);
}

unsigned long mapping_sizes[NR_MAPPING_SIZES] = {
	-1,	/* over-written with page_size below */
	MB(1), MB(2), MB(4), MB(10),
	GB(1),
};

static void setup_mapping_sizes(void)
{
	FILE *fp;
	char *buffer;
	size_t n = 0;

	mapping_sizes[0] = page_size;

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return;

	buffer = malloc(4096);
	if (!buffer)
		goto out_close;

	while (getline(&buffer, &n, fp) >= 0) {
		unsigned long long free;

		if (sscanf(buffer, "MemFree:         %llu", &free) == 1) {
			if ((free * 1024) < GB(8ULL)) {
				printf("Free memory: %.2fGB\n", (double) free / 1024 / 1024);
				printf("Low on memory, disabling mmaping of 1GB pages\n");
				mapping_sizes[5] = page_size;
				goto out_free;
			}
		}
	}

	//FIXME
	mapping_sizes[5] = page_size;

out_free:
	free(buffer);
out_close:
	fclose(fp);
}

void setup_initial_mappings(void)
{
	struct objhead *head;
	unsigned int i;

	head = get_objhead(OBJ_GLOBAL, OBJ_MMAP);
	head->destroy = &map_destructor;

	setup_mapping_sizes();

	for (i = 0; i < ARRAY_SIZE(mapping_sizes); i++) {
		alloc_zero_map(mapping_sizes[i], PROT_READ | PROT_WRITE, "PROT_READ | PROT_WRITE");
		alloc_zero_map(mapping_sizes[i], PROT_READ, "PROT_READ");
		alloc_zero_map(mapping_sizes[i], PROT_WRITE, "PROT_WRITE");
	}

	dump_initial_mappings();
}

void destroy_initial_mappings(void)
{
	struct list_head *node, *list, *tmp;
	struct objhead *head;

	head = &shm->global_objects[OBJ_MMAP];
	list = head->list;

	list_for_each_safe(node, tmp, list) {
		struct object *obj;

		obj = (struct object *) node;

		destroy_object(obj, OBJ_GLOBAL, OBJ_MMAP);
	}

	head->num_entries = 0;
}
