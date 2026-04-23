/*
 * Routines to dirty/fault-in mapped pages.
 */

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>	// getpagesize
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"	// get_address
#include "utils.h"

static bool mark_map_rw(struct map *map)
{
	int prot = PROT_READ | PROT_WRITE;
	int ret;

	ret = mprotect(map->ptr, map->size, prot);
	if (ret < 0) {
		log_mprotect_failure(map->ptr, (size_t) map->size, prot,
				     __builtin_return_address(0), errno);
		return false;
	}

	map->prot = prot;
	return true;
}

static bool mark_page_rw(void *page)
{
	int prot = PROT_READ | PROT_WRITE;
	int ret;

	ret = mprotect(page, page_size, prot);
	if (ret < 0) {
		log_mprotect_failure(page, (size_t) page_size, prot,
				     __builtin_return_address(0), errno);
		return false;
	}

	return true;
}

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void dirty_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset;

	if (map->size == 0)
		return;

	offset = (rand() % map->size) & PAGE_MASK;

	if (mark_page_rw(p + offset) == true)
		p[offset] = rand();
}

static void dirty_whole_mapping(struct map *map)
{
	unsigned int i, nr;

	if (mark_map_rw(map) == false)
		return;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		char *p = map->ptr + (i * page_size);
		*p = rand();
	}
}

static void dirty_every_other_page(struct map *map)
{
	unsigned int i, nr, first;

	nr = nr_pages(map);

	first = RAND_BOOL();

	for (i = first; i < nr; i+=2) {
		char *p = map->ptr + (i * page_size);
		if (mark_page_rw(p) == true)
			*p = rand();
	}
}

static void dirty_mapping_reverse(struct map *map)
{
	unsigned int i, nr;

	if (nr_pages(map) == 0)
		return;

	nr = nr_pages(map) - 1;

	for (i = nr; ; i--) {
		char *p = map->ptr + (i * page_size);
		if (mark_page_rw(p) == true)
			*p = rand();
		if (i == 0)
			break;
	}
}

/* dirty a random set of map->size pages. (some may be faulted >once) */
static void dirty_random_pages(struct map *map)
{
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		off_t offset = (rand() % nr) * page_size;
		char *p = map->ptr + offset;
		if (mark_page_rw(p) == true)
			*p = rand();
	}
}

static void dirty_first_page(struct map *map)
{
	char *p = map->ptr;

	if (mark_page_rw(map->ptr) == true)
		generate_random_page(p);
}

/* Dirty the last page in a mapping
 * Fill it with ascii, in the hope we do something like
 * a strlen and go off the end. */
static void dirty_last_page(struct map *map)
{
	char *p;

	if (map->size < page_size)
		return;

	p = map->ptr + map->size - page_size;

	if (mark_page_rw(p) == true)
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
		write_faultfns_single[rand() % ARRAY_SIZE(write_faultfns_single)].func(map);
	} else {
		if (RAND_BOOL()) {
			write_faultfns[rand() % ARRAY_SIZE(write_faultfns)].func(map);
		} else {
			write_faultfns_single[rand() % ARRAY_SIZE(write_faultfns_single)].func(map);
		}
	}
}
