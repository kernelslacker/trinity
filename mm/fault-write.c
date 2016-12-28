/*
 * Routines to dirty/fault-in mapped pages.
 */

#include <unistd.h>	// getpagesize
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"	// get_address
#include "utils.h"

static bool mark_map_rw(struct map *map)
{
	int ret;
	ret = mprotect(map->ptr, map->size, PROT_READ|PROT_WRITE);
	if (ret < 0)
		return FALSE;

	map->prot = PROT_READ|PROT_WRITE;
	return TRUE;
}

static bool mark_page_rw(struct map *map, void *page)
{
	int ret;
	ret = mprotect(page, page_size, PROT_READ|PROT_WRITE);
	if (ret < 0)
		return FALSE;

	map->prot = PROT_READ|PROT_WRITE;
	return TRUE;
}

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void dirty_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset = (rnd() % map->size) & PAGE_MASK;

	if (mark_page_rw(map, p + offset) == TRUE)
		p[offset] = rnd();
}

static void dirty_whole_mapping(struct map *map)
{
	unsigned int i, nr;

	if (mark_map_rw(map) == FALSE)
		return;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		char *p = map->ptr + (i * page_size);
		*p = rnd();
	}
}

static void dirty_every_other_page(struct map *map)
{
	unsigned int i, nr, first;

	nr = nr_pages(map);

	first = RAND_BOOL();

	for (i = first; i < nr; i+=2) {
		char *p = map->ptr + (i * page_size);
		if (mark_page_rw(map, p) == TRUE)
			*p = rnd();
	}
}

static void dirty_mapping_reverse(struct map *map)
{
	unsigned int i, nr;

	nr = nr_pages(map) - 1;

	for (i = nr; i > 0; i--) {
		char *p = map->ptr + (i * page_size);
		if (mark_page_rw(map, p) == TRUE)
			*p = rnd();
	}
}

/* dirty a random set of map->size pages. (some may be faulted >once) */
static void dirty_random_pages(struct map *map)
{
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		off_t offset = (rnd() % nr) * page_size;
		char *p = map->ptr + offset;
		if (mark_page_rw(map, p) == TRUE)
			*p = rnd();
	}
}

/*
 */
static void dirty_first_page(struct map *map)
{
	char *p = map->ptr;

	if (mark_page_rw(map, map->ptr) == TRUE)
		generate_random_page(p);
}

/* Dirty the last page in a mapping
 * Fill it with ascii, in the hope we do something like
 * a strlen and go off the end. */
static void dirty_last_page(struct map *map)
{
	char *p = map->ptr + map->size - page_size;

	if (mark_page_rw(map, p) == TRUE)
		memset((void *) p, 'A', page_size);
}

static const struct faultfn write_faultfns_single[] = {
	{ .func = dirty_one_page },
	{ .func = dirty_first_page },
};

static const struct faultfn write_faultfns[] = {
	{ .func = dirty_whole_mapping },
	{ .func = dirty_every_other_page },
	{ .func = dirty_mapping_reverse },
	{ .func = dirty_random_pages },
	{ .func = dirty_last_page },
};

void random_map_writefn(struct map *map)
{
	if (map->size == page_size) {
		write_faultfns_single[rnd() % ARRAY_SIZE(write_faultfns_single)].func(map);
	} else {
		if (RAND_BOOL()) {
			write_faultfns[rnd() % ARRAY_SIZE(write_faultfns)].func(map);
		} else {
			write_faultfns_single[rnd() % ARRAY_SIZE(write_faultfns_single)].func(map);
		}
	}
}
