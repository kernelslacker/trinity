/*
 * Routines to fault-in mapped pages.
 */

#include <errno.h>
#include <sys/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "utils.h"

/* 64KB covers the largest page size (arm64 with 64KB pages). */
static char page_buf[65536];

/*
 * Wrapper so every read-side mprotect() in this file logs a structured
 * failure line (PROT bits + region size + caller PC) instead of the
 * original "silently ignore non-zero returns" behaviour.  The reader
 * still proceeds to the memcpy on failure — pages already mapped with
 * a stricter prot will just satisfy the read regardless, and a true
 * EFAULT surfaces in the memcpy where we can't do anything more useful
 * about it.
 */
static void read_mprotect(void *addr, size_t len, int prot)
{
	if (mprotect(addr, len, prot) != 0)
		log_mprotect_failure(addr, len, prot,
				     __builtin_return_address(0), errno);
}

static unsigned int nr_pages(struct map *map)
{
	return map->size / page_size;
}

static void read_one_page(struct map *map)
{
	char *p = map->ptr;
	unsigned long offset;

	if (map->size == 0)
		return;

	offset = (rand() % map->size) & PAGE_MASK;

	p += offset;
	read_mprotect((void *) p, page_size, PROT_READ);
	memcpy(page_buf, p, page_size);
}


static void read_whole_mapping(struct map *map)
{
	char *p = map->ptr;
	unsigned int i, nr;

	nr = nr_pages(map);

	for (i = 0; i < nr; i++) {
		char *page = p + (i * page_size);
		read_mprotect((void *) page, page_size, PROT_READ);
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
		read_mprotect((void *) page, page_size, PROT_READ);
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

	for (i = nr; ; i--) {
		char *page = p + (i * page_size);
		read_mprotect((void *) page, page_size, PROT_READ);
		memcpy(page_buf, page, page_size);
		if (i == 0)
			break;
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
		read_mprotect((void *) page, page_size, PROT_READ);
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
	read_mprotect((void *) ptr, page_size, PROT_READ);
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
