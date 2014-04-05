/*
 * Routines to dirty/fault-in mapped pages.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "utils.h"

/*****************************************************************************/
/* dirty page routines */

static void dirty_one_page(struct map *map)
{
	char *p = map->ptr;

	p[rand() % map->size] = rand();
}

static void dirty_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;

	for (i = 0; i < map->size; i += page_size)
		p[i] = rand();
}

static void dirty_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;

	for (i = 0; i < map->size; i += (page_size * 2))
		p[i] = rand();
}

static void dirty_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;

	for (i = (map->size - page_size); i > 0; i -= page_size)
		p[i] = rand();
}

/* dirty a random set of map->size pages. (some may be faulted >once) */
static void dirty_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;
	unsigned int num_pages = map->size / page_size;

	for (i = 0; i < num_pages; i++)
		p[(rand() % (num_pages + 1)) * page_size] = rand();
}

/* Dirty the last page in a mapping
 * Fill it with ascii, in the hope we do something like
 * a strlen and go off the end. */
static void dirty_last_page(struct map *map)
{
	char *p = map->ptr;

	memset((void *) p + (map->size - page_size), 'A', page_size);
}

struct faultfn {
	void (*func)(struct map *map);
};

/*****************************************************************************/
/* routines to fault in pages */

static void read_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset = (rand() % map->size) & PAGE_MASK;
	char buf[page_size];

	p += offset;
	memcpy(buf, p, page_size);
}


static void read_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;
	char buf[page_size];

	for (i = 0; i < map->size; i += page_size)
		memcpy(buf, p + i, page_size);
}

static void read_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;
	char buf[page_size];

	for (i = 0; i < map->size; i += (page_size * 2))
		memcpy(buf, p + i, page_size);
}

static void read_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;
	char buf[page_size];

	for (i = (map->size - page_size); i > 0; i -= page_size)
		memcpy(buf, p + i, page_size);
}

/* fault in a random set of map->size pages. (some may be faulted >once) */
static void read_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i;
	unsigned int num_pages = map->size / page_size;
	char buf[page_size];

	for (i = 0; i < num_pages; i++)
		memcpy(buf, p + ((rand() % (num_pages + 1)) * page_size), page_size);
}

/* Fault in the last page in a mapping */
static void read_last_page(struct map *map)
{
	char *p = map->ptr;
	char buf[page_size];

	memcpy(buf, p + (map->size - page_size), page_size);
}


/*****************************************************************************/

static const struct faultfn write_faultfns[] = {
	{ .func = dirty_one_page },
	{ .func = dirty_whole_mapping },
	{ .func = dirty_every_other_page },
	{ .func = dirty_mapping_reverse },
	{ .func = dirty_random_pages },
	{ .func = dirty_last_page },
};

static const struct faultfn read_faultfns[] = {
	{ .func = read_one_page },
	{ .func = read_whole_mapping },
	{ .func = read_every_other_page },
	{ .func = read_mapping_reverse },
	{ .func = read_random_pages },
	{ .func = read_last_page },
};

/*
 * Routine to perform various kinds of write operations to a mapping
 * that we created.
 */
void dirty_mapping(struct map *map)
{
	bool rw = rand_bool();

	if (rw == TRUE) {
		/* Check mapping is writable, or we'll segv.
		 * TODO: Perhaps we should do that, and trap it, mark it writable,
		 * then reprotect after we dirtied it ? */
		if (!(map->prot & PROT_WRITE))
			return;

		write_faultfns[rand() % ARRAY_SIZE(write_faultfns)].func(map);
		return;
	} else {
		if (!(map->prot & PROT_READ))
			return;

		read_faultfns[rand() % ARRAY_SIZE(read_faultfns)].func(map);
	}

}
