/*
 * Routines to fault-in mapped pages.
 */

#include "arch.h"
#include "maps.h"
#include "random.h"
#include "utils.h"

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void read_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset = (rnd() % map->size) & PAGE_MASK;
	char buf[page_size];

	p += offset;
	mprotect((void *) p, page_size, PROT_READ);
	memcpy(buf, p, page_size);
}


static void read_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;
	char buf[page_size];

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		char *page = p + (i * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(buf, page, page_size);
	}
}

static void read_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr, first;
	char buf[page_size];

	nr = nr_pages(map);

	first = RAND_BOOL();

	for (i = first; i < nr; i+=2) {
		char *page = p + (i * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(buf, page, page_size);
	}
}

static void read_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;
	char buf[page_size];

	nr = nr_pages(map) - 1;

	for (i = nr; i > 0; i--) {
		char *page = p + (i * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(buf, page, page_size);
	}
}

/* fault in a random set of map->size pages. (some may be faulted >once) */
static void read_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;
	char buf[page_size];

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		char *page = p + ((rnd() % nr) * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(buf, page, page_size);
	}
}

/* Fault in the last page in a mapping */
static void read_last_page(struct map *map)
{
	char *p = map->ptr;
	char buf[page_size];
	char *ptr;

	ptr = p + (map->size - page_size);
	mprotect((void *) ptr, page_size, PROT_READ);
	memcpy(buf, ptr, page_size);
}

static const struct faultfn read_faultfns[] = {
	{ .func = read_whole_mapping },
	{ .func = read_every_other_page },
	{ .func = read_mapping_reverse },
	{ .func = read_random_pages },
	{ .func = read_last_page },
};

void random_map_readfn(struct map *map)
{
	if (map->size == page_size)
		read_one_page(map);
	else {
		if (RAND_BOOL())
			read_one_page(map);
		else
			read_faultfns[rnd() % ARRAY_SIZE(read_faultfns)].func(map);
	}
}
