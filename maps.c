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
#include "arch.h"
#include "child.h"
#include "list.h"
#include "log.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"	// page_size
#include "utils.h"

static unsigned int num_global_mappings = 0;
static struct map *global_mappings = NULL;

static void dump_global_mappings(void)
{
	struct map *m;
	struct list_head *node;

	output(2, "There are %d entries in the map table\n", num_global_mappings);

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

	num_global_mappings++;

	list = &global_mappings->list;
	list_add_tail(&newnode->list, list);

	output(2, "mapping[%d]: (zeropage %s) %p (%lu bytes)\n",
			num_global_mappings - 1, name, newnode->ptr, size);

	close(fd);
}

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
static struct map * __get_map(struct list_head *head, unsigned int max)
{
	struct map *m;
	struct list_head *node;

	unsigned int i, j = 0;

	i = rand() % max;

	list_for_each(node, head) {
		m = (struct map *) node;

		if (i == j)
			return m;
		j++;
	}
	return 0;
}

struct map * get_map(void)
{
	struct map *map;
	bool local = FALSE;

	/* If we're not running in child context, just do global. */
	if (this_child == 0)
		return __get_map(&global_mappings->list, num_global_mappings);

	/* Only toss the dice if we actually have local mappings. */
	if (shm->num_mappings[this_child] > 0)
		local = rand_bool();

	if (local == TRUE)
		map = __get_map(&shm->mappings[this_child]->list, shm->num_mappings[this_child]);
	else
		map = __get_map(&global_mappings->list, num_global_mappings);

	return map;
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

	num_global_mappings = 0;
}

void delete_local_mapping(int childno, struct map *map)
{
	list_del(&map->list);
	shm->num_mappings[childno]--;
}

struct map * common_set_mmap_ptr_len(int childno)
{
	struct map *map;

	map = (struct map *) shm->a1[childno];
	shm->scratch[childno] = (unsigned long) map;    /* Save this for ->post */
	if (map == NULL) {
		shm->a1[childno] = 0;
		shm->a2[childno] = 0;
		return NULL;
	}

	shm->a1[childno] = (unsigned long) map->ptr;
	shm->a2[childno] = map->size;           //TODO: Munge this.

	return map;
}

void dirty_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;

	/* Check mapping is writable. */
	if (!(map->prot & PROT_WRITE))
		return;

	if (rand_bool()) {
		/* Just fault in one page. */
		p[rand() % page_size] = 1;
	} else {
		/* fault in the whole mapping */
		for (i = 0; i < map->size; i += page_size)
			p[i] = 1;
	}
	//TODO: More access patterns.
}
