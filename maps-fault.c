/*
 * Routines to dirty/fault-in mapped pages.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>	// getpagesize
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"	// get_address
#include "utils.h"

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

struct faultfn {
	void (*func)(struct map *map);
};

/*****************************************************************************/
/* dirty page routines */

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

			if (rand_bool())
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
		memset(page, rand() % 0xff, page_size);
		return;

	case 3:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rand();
		return;

	case 4:
		for (i = 0; i < page_size; )
			page[i++] = (unsigned char)rand_bool();
		return;

	/* return a page that looks kinda like a struct */
	case 5:	fabricate_onepage_struct(page);
		return;

	/* page full of format strings. */
	case 6:
		for (i = 0; i < page_size; i += 2) {
			page[i] = '%';
			switch (rand_bool()) {
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
			case 0:	p = sprintf(page, "%lu", (unsigned long) rand64());
				break;
			case 1:	p = sprintf(page, "%ld", (unsigned long) rand64());
				break;
			case 2:	p = sprintf(page, "%lx", (unsigned long) rand64());
				break;
			}
			break;

		case 1:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%u", (unsigned int) rand32());
				break;
			case 1:	p = sprintf(page, "%d", (int) rand32());
				break;
			case 2:	p = sprintf(page, "%x", (int) rand32());
				break;
			}
			break;

		case 2:
			switch (rand() % 3) {
			case 0:	p = sprintf(page, "%u", (unsigned char) rand());
				break;
			case 1:	p = sprintf(page, "%d", (char) rand());
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

	first = rand_bool();

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

	memset((void *) p + ((map->size - 1) - page_size), 'A', page_size);
}

static const struct faultfn write_faultfns[] = {
	{ .func = dirty_one_page },
	{ .func = dirty_whole_mapping },
	{ .func = dirty_every_other_page },
	{ .func = dirty_mapping_reverse },
	{ .func = dirty_random_pages },
	{ .func = dirty_first_page },
	{ .func = dirty_last_page },
};

/*****************************************************************************/
/* routines to fault in pages */

static void read_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset = (rand() % (map->size - 1)) & PAGE_MASK;
	char buf[page_size];

	p += offset;
	memcpy(buf, p, page_size);
}


static void read_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;
	char buf[page_size];

	nr = nr_pages(map);

	for (i = 0; i < nr; i++)
		memcpy(buf, p + (i * page_size), page_size);
}

static void read_every_other_page(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr, first;
	char buf[page_size];

	nr = nr_pages(map);

	first = rand_bool();

	for (i = first; i < nr; i+=2)
		memcpy(buf, p + (i * page_size), page_size);
}

static void read_mapping_reverse(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;
	char buf[page_size];

	nr = nr_pages(map) - 1;

	for (i = nr; i > 0; i--)
		memcpy(buf, p + (i * page_size), page_size);
}

/* fault in a random set of map->size pages. (some may be faulted >once) */
static void read_random_pages(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;
	char buf[page_size];

	nr = nr_pages(map);

	for (i = 0; i < nr; i++)
		memcpy(buf, p + ((rand() % nr) * page_size), page_size);
}

/* Fault in the last page in a mapping */
static void read_last_page(struct map *map)
{
	char *p = map->ptr;
	char buf[page_size];

	memcpy(buf, p + ((map->size - 1) - page_size), page_size);
}

static const struct faultfn read_faultfns[] = {
	{ .func = read_one_page },
	{ .func = read_whole_mapping },
	{ .func = read_every_other_page },
	{ .func = read_mapping_reverse },
	{ .func = read_random_pages },
	{ .func = read_last_page },
};

/*****************************************************************************/

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
