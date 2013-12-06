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
static struct map *maps = NULL;

char *page_zeros;
char *page_0xff;
char *page_rand;
char *page_allocs;

void * alloc_shared(unsigned int size)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
	if (ret == MAP_FAILED)
		return NULL;

	return ret;
}

static void dump_maps(void)
{
	struct map *m;
	struct list_head *node;

	output(2, "There are %d entries in the map table\n", num_mappings);

	list_for_each(node, &maps->list) {
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

	list = &maps->list;
	list_add_tail(&newnode->list, list);

	output(2, "mapping[%d]: (zeropage %s) %p (%lu bytes)\n",
			num_mappings - 1, name, newnode->ptr, size);

	close(fd);
}

#define MB (1024 * 1024UL)
#define GB (1024 * MB)

void setup_maps(void)
{
	unsigned int i;
	const unsigned long sizes[] = {
		1 * MB, 2 * MB, 4 * MB, 10 * MB,
//		1 * GB,	// disabled for now, due to OOM.
	};

	maps = zmalloc(sizeof(struct map));
	INIT_LIST_HEAD(&maps->list);

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

	dump_maps();
}

/* Walk the list, get the j'th element */
struct map * get_map(void)
{
	struct map *m;
	struct list_head *node;
	unsigned int i, j = 0;

	i = rand() % num_mappings;

	list_for_each(node, &maps->list) {
		m = (struct map *) node;

		if (i == j)
			return m;
		j++;
	}
	return 0;
}

void destroy_maps(void)
{
	struct map *m = maps;

	while (!list_empty(&maps->list)) {
		m = maps;

		munmap(m->ptr, m->size);
		free(m->name);

		maps = (struct map *) m->list.next;

		list_del(&m->list);
		free(m);
	}
	num_mappings = 0;
}

void init_buffers(void)
{
	unsigned int i;

	output(2, "shm is at %p\n", shm);

	page_zeros = memalign(page_size, page_size * 2);
	if (!page_zeros)
		exit(EXIT_FAILURE);
	memset(page_zeros, 0, page_size);
	output(2, "page_zeros @ %p\n", page_zeros);

	page_0xff = memalign(page_size, page_size * 2);
	if (!page_0xff)
		exit(EXIT_FAILURE);
	memset(page_0xff, 0xff, page_size);
	output(2, "page_0xff @ %p\n", page_0xff);

	page_rand = memalign(page_size, page_size * 2);
	if (!page_rand)
		exit(EXIT_FAILURE);
	memset(page_rand, 0x55, page_size);	/* overwritten below */
	output(2, "page_rand @ %p\n", page_rand);

	page_allocs = memalign(page_size, page_size * 2);
	if (!page_allocs)
		exit(EXIT_FAILURE);
	memset(page_allocs, 0xff, page_size);
	output(2, "page_allocs @ %p\n", page_allocs);

	for (i = 0; i < (page_size / sizeof(unsigned long *)); i++)
		page_allocs[i] = (unsigned long) malloc(page_size);

	setup_maps();

	// generate_random_page may end up using maps, so has to be last.
	generate_random_page(page_rand);
}
