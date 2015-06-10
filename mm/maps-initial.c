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

unsigned int num_initial_mappings = 0;
struct map *initial_mappings = NULL;

static void dump_initial_mappings(void)
{
	struct list_head *node;

	output(2, "There are %d entries in the map table\n", num_initial_mappings);

	list_for_each(node, &initial_mappings->list) {
		struct map *m;

		m = (struct map *) node;
		output(2, " start: %p  name: %s\n", m->ptr, m->name);
	}
}

static void alloc_zero_map(unsigned long size, int prot, const char *name)
{
	struct map *newnode;
	int fd;
	char buf[11];

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		outputerr("couldn't open /dev/zero\n");
		exit(EXIT_FAILURE);
	}

	newnode = zmalloc(sizeof(struct map));
	newnode->name = strdup(name);
	newnode->size = size;
	newnode->prot = prot;
	newnode->type = TRINITY_MAP_INITIAL;
	newnode->ptr = mmap(NULL, size, prot, MAP_ANONYMOUS | MAP_SHARED, fd, 0);
	if (newnode->ptr == MAP_FAILED) {
		outputerr("mmap failure\n");
		exit(EXIT_FAILURE);
	}

	newnode->name = zmalloc(80);

	sprintf(newnode->name, "anon(%s)", name);

	num_initial_mappings++;

	list_add_tail(&newnode->list, &initial_mappings->list);

	sizeunit(size, buf);
	output(2, "mapping[%d]: (zeropage %s) %p (%s)\n",
			num_initial_mappings - 1, name, newnode->ptr, buf);

	close(fd);
}

void setup_initial_mappings(void)
{
	unsigned int i;
	const unsigned long sizes[] = {
		1 * MB, 2 * MB, 4 * MB, 10 * MB,
//		1 * GB,	// disabled for now, due to OOM.
	};

	initial_mappings = zmalloc(sizeof(struct map));
	INIT_LIST_HEAD(&initial_mappings->list);

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
	struct list_head *node, *tmp;
	struct map *m;

	list_for_each_safe(node, tmp, &initial_mappings->list) {
		m = (struct map *) node;

		munmap(m->ptr, m->size);
		free(m->name);

		list_del(&m->list);
		free(m);
	}

	num_initial_mappings = 0;
}
