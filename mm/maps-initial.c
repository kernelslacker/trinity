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

		obj = (struct object *) node;
		m = &obj->map;
		output(2, " start: %p size:%d  name: %s\n", m->ptr, m->size, m->name);
	}
}

static void alloc_zero_map(unsigned long size, int prot, const char *name)
{
	struct objhead *head;
	struct object *new;
	int fd;
	char buf[11];

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		outputerr("couldn't open /dev/zero\n");
		exit(EXIT_FAILURE);
	}

	new = zmalloc(sizeof(struct object));
	new->map.name = strdup(name);
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

	head = &shm->global_objects[OBJ_MMAP];

	add_object(new, OBJ_GLOBAL, OBJ_MMAP);

	sizeunit(size, buf);
	output(2, "mapping[%d]: (zeropage %s) %p (%s)\n",
			head->num_entries - 1, name, new->map.ptr, buf);

	close(fd);
}

void setup_initial_mappings(void)
{
	unsigned int i;
	const unsigned long sizes[] = {
		MB(1), MB(2), MB(4), MB(10),
//		GB(1),	// disabled for now, due to OOM.
	};

	init_object_lists(OBJ_GLOBAL);

	alloc_zero_map(page_size, PROT_READ | PROT_WRITE, "PROT_READ | PROT_WRITE");
	alloc_zero_map(page_size, PROT_READ, "PROT_READ");
	alloc_zero_map(page_size, PROT_WRITE, "PROT_WRITE");

	/*
	 * multi megabyte page mappings.
	 */
	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		alloc_zero_map(sizes[i], PROT_READ | PROT_WRITE, "PROT_READ | PROT_WRITE");
		alloc_zero_map(sizes[i], PROT_READ, "PROT_READ");
		alloc_zero_map(sizes[i], PROT_WRITE, "PROT_WRITE");
	}

	dump_initial_mappings();
}

void destroy_initial_mappings(void)
{
	struct list_head *node, *list, *tmp;
	struct objhead *head;
	struct map *m;

	head = &shm->global_objects[OBJ_MMAP];
	list = head->list;

	list_for_each_safe(node, tmp, list) {
		m = (struct map *) node;

		munmap(m->ptr, m->size);
		free(m->name);

		destroy_object((struct object *) m, OBJ_GLOBAL, OBJ_MMAP);
	}

	head->num_entries = 0;
}
