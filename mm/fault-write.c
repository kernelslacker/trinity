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

static void fabricate_onepage_struct(char *page)
{
	unsigned int i;

	for (i = 0; i < page_size; ) {
		void **ptr;

		ptr = (void*) &page[i];

		/* 4 byte (32bit) 8 byte (64bit) alignment */
		if (i & ~((__WORDSIZE / 8) - 1)) {
			unsigned long val;

			i += sizeof(unsigned long);
			if (i > page_size)
				return;

			if (RAND_BOOL())
				val = rand64();
			else
				val = (unsigned long) get_address();

			*(unsigned long *)ptr = val;

		} else {
			/* int alignment */

			i += sizeof(unsigned int);
			if (i > page_size)
				return;

			*(unsigned int *)ptr = rand32();
		}
	}
}

static void generate_random_page(char *page)
{
	unsigned int i;
	unsigned int p = 0;

	switch (rand() % 8) {

	case 0:
		memset(page, 0, page_size);
		return;

	case 1:
		memset(page, 0xff, page_size);
		return;

	case 2:
		memset(page, RAND_BYTE(), page_size);
		return;

	case 3:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rand();
		return;

	case 4:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)RAND_BOOL();
		return;

	/* return a page that looks kinda like a struct */
	case 5:	fabricate_onepage_struct(page);
		return;

	/* page full of format strings. */
	case 6:
		for (i = 0; i < page_size; i += 2) {
			page[i] = '%';
			switch (RAND_BOOL()) {
			case 0:	page[i + 1] = 'd';
				break;
			case 1:	page[i + 1] = 's';
				break;
			}
		}
		page_size = getpagesize();	// Hack for clang 3.3 false positive.
		page[rand() % page_size] = 0;
		return;

	/* ascii representation of a random number */
	case 7:
		switch (rand() % 3) {
		case 0:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%s%lu",
					RAND_BOOL() ? "-" : "",
					(unsigned long) rand64());
				break;
			case 1:	p = sprintf(page, "%s%ld",
					RAND_BOOL() ? "-" : "",
					(unsigned long) rand64());
				break;
			case 2:	p = sprintf(page, "%lx", (unsigned long) rand64());
				break;
			}
			break;

		case 1:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%s%u",
					RAND_BOOL() ? "-" : "",
					(unsigned int) rand32());
				break;
			case 1:	p = sprintf(page, "%s%d",
					RAND_BOOL() ? "-" : "",
					(int) rand32());
				break;
			case 2:	p = sprintf(page, "%x", (int) rand32());
				break;
			}
			break;

		case 2:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%s%u",
					RAND_BOOL() ? "-" : "",
					(unsigned char) rand());
				break;
			case 1:	p = sprintf(page, "%s%d",
					RAND_BOOL() ? "-" : "",
					(char) rand());
				break;
			case 2:	p = sprintf(page, "%x", (char) rand());
				break;
			}
			break;

		}

		page[p] = 0;
		break;
	}
}


static void dirty_one_page(struct map *map)
{
	char *p = map->ptr;

	p[rand() % (map->size - 1)] = rand();
}

static void dirty_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++)
		p[i * page_size] = rand();
}

static void dirty_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr, first;

	nr = nr_pages(map);

	first = RAND_BOOL();

	for (i = first; i < nr; i+=2)
		p[i * page_size] = rand();
}

static void dirty_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map) - 1;

	for (i = nr; i > 0; i--)
		p[i * page_size] = rand();
}

/* dirty a random set of map->size pages. (some may be faulted >once) */
static void dirty_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++)
		p[(rand() % nr) * page_size] = rand();
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
	char *p = map->ptr;

	memset((void *) p + (map->size - page_size), 'A', page_size);
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
	if (map->size == page_size)
		write_faultfns_single[rand() % ARRAY_SIZE(write_faultfns_single)].func(map);
	else {
		if (RAND_BOOL())
			write_faultfns[rand() % ARRAY_SIZE(write_faultfns)].func(map);
		else
			write_faultfns_single[rand() % ARRAY_SIZE(write_faultfns_single)].func(map);
	}
}
