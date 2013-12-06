#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "trinity.h"	// page_size
#include "arch.h"
#include "maps.h"
#include "list.h"
#include "log.h"
#include "shm.h"
#include "utils.h"

static unsigned int num_mappings = 0;
static struct map *global_mappings = NULL;

static void dump_global_mappings(void)
{
	struct map *m;
	struct list_head *node;

	output(2, "There are %d entries in the map table\n", num_mappings);

	list_for_each(node, &global_mappings->list) {
		m = (struct map *) node;
		output(2, " start: %p  name: %s\n", m->ptr, m->name);
	}
}

static void alloc_zero_map(unsigned long size, int prot, const char *name)
{
	struct map *newnode;
	struct list_head *list;
	int fd;

	fd = open("/dev/zero", O_RDWR);

	newnode = zmalloc(sizeof(struct map));
	newnode->name = strdup(name);
	newnode->size = size;
	newnode->prot = prot;
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

	num_mappings++;

	list = &global_mappings->list;
	list_add_tail(&newnode->list, list);

	output(2, "mapping[%d]: (zeropage %s) %p (%lu bytes)\n",
			num_mappings - 1, name, newnode->ptr, size);

	close(fd);
}

#define MB (1024 * 1024UL)
#define GB (1024 * MB)

void setup_global_mappings(void)
{
	unsigned int i;
	const unsigned long sizes[] = {
		1 * MB, 2 * MB, 4 * MB, 10 * MB,
//		1 * GB,	// disabled for now, due to OOM.
	};

	global_mappings = zmalloc(sizeof(struct map));
	INIT_LIST_HEAD(&global_mappings->list);

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

	dump_global_mappings();
}

/* Walk the list, get the j'th element */
struct map * get_map(void)
{
	struct map *m;
	struct list_head *node;
	unsigned int i, j = 0;

	i = rand() % num_mappings;

	list_for_each(node, &global_mappings->list) {
		m = (struct map *) node;

		if (i == j)
			return m;
		j++;
	}
	return 0;
}

void destroy_global_mappings(void)
{
	struct map *m = global_mappings;

	while (!list_empty(&global_mappings->list)) {
		m = global_mappings;

		munmap(m->ptr, m->size);
		free(m->name);

		global_mappings = (struct map *) m->list.next;

		list_del(&m->list);
		free(m);
	}

	num_mappings = 0;
}
