/*
 * Routines to dirty/fault-in mapped pages.
 */

#include <unistd.h>	// getpagesize
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"	// get_address
#include "utils.h"

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void dirty_one_page(struct map *map)
{
	char *p = map->ptr;

	p[rnd() % (map->size - 1)] = rnd();
}

static void dirty_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++)
		p[i * page_size] = rnd();
}

static void dirty_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr, first;

	nr = nr_pages(map);

	first = RAND_BOOL();

	for (i = first; i < nr; i+=2)
		p[i * page_size] = rnd();
}

static void dirty_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map) - 1;

	for (i = nr; i > 0; i--)
		p[i * page_size] = rnd();
}

/* dirty a random set of map->size pages. (some may be faulted >once) */
static void dirty_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++)
		p[(rnd() % nr) * page_size] = rnd();
}

/*
 */
static void dirty_first_page(struct map *map)
{
	char *p = map->ptr;

	generate_random_page(p);
}

/* Dirty the last page in a mapping
 * Fill it with ascii, in the hope we do something like
 * a strlen and go off the end. */
static void dirty_last_page(struct map *map)
{
	char *p = map->ptr + map->size - page_size;

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
		mprotect(map->ptr, page_size, PROT_READ|PROT_WRITE);
		write_faultfns_single[rnd() % ARRAY_SIZE(write_faultfns_single)].func(map);
	} else {
		if (RAND_BOOL()) {
			mprotect(map->ptr, map->size, PROT_READ|PROT_WRITE);
			write_faultfns[rnd() % ARRAY_SIZE(write_faultfns)].func(map);
		} else {
			mprotect(map->ptr, page_size, PROT_READ|PROT_WRITE);
			write_faultfns_single[rnd() % ARRAY_SIZE(write_faultfns_single)].func(map);
		}
	}
}
