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

char *page_zeros;
char *page_0xff;
char *page_rand;
unsigned long *page_allocs;
unsigned long *page_maps;

static void * __allocbuf(const char *name)
{
	void *ptr;

	ptr = memalign(page_size, page_size * 2);
	if (!ptr)
		exit(EXIT_FAILURE);
	memset(ptr, 0, page_size * 2);
	output(2, "%s @ %p\n", name, ptr);
	return ptr;
}

void init_shared_pages(void)
{
	unsigned int i;

	output(2, "shm is at %p\n", shm);

	// a page of zeros
	page_zeros = __allocbuf("page_zeros");

	// a page of 0xff
	page_0xff = __allocbuf("page_0xff");

	// a page of random crap (overwritten below)
	page_rand = __allocbuf("page_rand");

	// page containing ptrs to mallocs.
	page_allocs = __allocbuf("page_allocs");
	for (i = 0; i < (page_size / sizeof(unsigned long *)); i++)
		page_allocs[i] = (unsigned long) malloc(page_size);

	// a page of ptrs to mmaps (set up at child init time).
	page_maps = __allocbuf("page_maps");

	// mmaps that get shared across children.
	setup_global_mappings();

	// generate_random_page may end up using global_mappings, so has to be last.
	generate_random_page(page_rand);
}


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
	struct map *m;

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

static void delete_local_mapping(int childno, struct map *map)
{
	list_del(&map->list);
	shm->num_mappings[childno]--;
}

void delete_mapping(int childno, struct map *map)
{
	if (map->type == MAP_LOCAL)
		delete_local_mapping(childno, map);

	/* Right now, we don't want to delete MAP_GLOBAL mappings */
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
