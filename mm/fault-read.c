/*
 * Routines to fault-in mapped pages.
 */

#include "arch.h"
#include "maps.h"
#include "random.h"
#include "utils.h"

/* 64KB covers the largest page size (arm64 with 64KB pages). */
static char page_buf[65536];

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void read_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset = (rand() % map->size) & PAGE_MASK;

	p += offset;
	mprotect((void *) p, page_size, PROT_READ);
	memcpy(page_buf, p, page_size);
}


static void read_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		char *page = p + (i * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

static void read_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr, first;

	nr = nr_pages(map);

	first = RAND_BOOL();

	for (i = first; i < nr; i+=2) {
		char *page = p + (i * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

static void read_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	if (nr_pages(map) == 0)
		return;

	nr = nr_pages(map) - 1;

	for (i = nr; i > 0; i--) {
		char *page = p + (i * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

/* fault in all pages of the mapping. */
static void read_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		char *page = p + ((rand() % nr) * page_size);
		mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
	}
}

/* Fault in the last page in a mapping */
static void read_last_page(struct map *map)
{
	char *p = map->ptr;
	char *ptr;

	if (map->size < page_size)
		return;

	ptr = p + (map->size - page_size);
	mprotect((void *) ptr, page_size, PROT_READ);
	memcpy(page_buf, ptr, page_size);
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
			read_faultfns[rand() % ARRAY_SIZE(read_faultfns)].func(map);
	}
}
