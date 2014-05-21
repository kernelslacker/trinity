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

unsigned int num_shared_mappings = 0;
struct map *shared_mappings = NULL;

static void dump_shared_mappings(void)
{
	struct list_head *node;

	output(2, "There are %d entries in the map table\n", num_shared_mappings);

	list_for_each(node, &shared_mappings->list) {
		struct map *m;

		m = (struct map *) node;
		output(2, " start: %p  name: %s\n", m->ptr, m->name);
	}
}

static void alloc_zero_map(unsigned long size, int prot, const char *name)
{
	struct map *newnode;
	struct list_head *list;
	int fd;
	char buf[10];

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		outputerr("couldn't open /dev/zero\n");
		exit(EXIT_FAILURE);
	}

	newnode = zmalloc(sizeof(struct map));
	newnode->name = strdup(name);
	newnode->size = size;
	newnode->prot = prot;
	newnode->type = MAP_GLOBAL;
	newnode->ptr = mmap(NULL, size, prot, MAP_ANONYMOUS | MAP_SHARED, fd, 0);
	if (newnode->ptr == MAP_FAILED) {
		outputerr("mmap failure\n");
		exit(EXIT_FAILURE);
	}

	newnode->name = malloc(80);
	if (!newnode->name) {
		outputerr("malloc() failed in %s().", __func__);
		exit(EXIT_FAILURE);
	}

	sprintf(newnode->name, "anon(%s)", name);

	num_shared_mappings++;

	if (shared_mappings == NULL) {
		shared_mappings = newnode;
		INIT_LIST_HEAD(&shared_mappings->list);
	} else {
		list = &shared_mappings->list;
		list_add_tail(&newnode->list, list);
	}

	sizeunit(size, buf);
	output(2, "mapping[%d]: (zeropage %s) %p (%s)\n",
			num_shared_mappings - 1, name, newnode->ptr, buf);

	close(fd);
}

void setup_shared_mappings(void)
{
	unsigned int i;
	const unsigned long sizes[] = {
		1 * MB, 2 * MB, 4 * MB, 10 * MB,
//		1 * GB,	// disabled for now, due to OOM.
	};

	/* page_size * 2, so we have a guard page afterwards.
	 * This is necessary for when we want to test page boundaries.
	 * see end of _get_address() for details.
	 */
	alloc_zero_map(page_size * 2, PROT_READ | PROT_WRITE, "PROT_READ | PROT_WRITE");
	alloc_zero_map(page_size * 2, PROT_READ, "PROT_READ");
	alloc_zero_map(page_size * 2, PROT_WRITE, "PROT_WRITE");

	/*
	 * multi megabyte page mappings.
	 */
	for (i = 0; i < ARRAY_SIZE(sizes); i++) {
		alloc_zero_map(sizes[i], PROT_READ | PROT_WRITE, "PROT_READ | PROT_WRITE");
		alloc_zero_map(sizes[i], PROT_READ, "PROT_READ");
		alloc_zero_map(sizes[i], PROT_WRITE, "PROT_WRITE");
	}

	dump_shared_mappings();
}

void destroy_shared_mappings(void)
{
	struct map *m;

	while (!list_empty(&shared_mappings->list)) {
		m = shared_mappings;

		munmap(m->ptr, m->size);
		free(m->name);

		shared_mappings = (struct map *) m->list.next;

		list_del(&m->list);
		free(m);
	}

	num_shared_mappings = 0;
}
