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

/*
 * Per-call upper bound on mark_page_rw() invocations.  Each mark_page_rw
 * is an mprotect(4096) that triggers a TLB shootdown IPI to every other
 * CPU running a thread of the same mm.  Walking N pages of a large
 * mapping in a tight loop generates an IPI storm proportional to N x
 * num_children.  The fuzz value of dirtying any one page after the first
 * few is marginal — the goal is "this VMA gets touched", not "every
 * page in this VMA gets touched".  Cap the per-call work; pages above
 * the cap get hit on a future tick instead.
 */
#define DIRTY_PAGES_PER_CALL_MAX	32U

static unsigned int dirty_walk_count(struct map *map)
{
	unsigned int nr = nr_pages(map);

	if (nr > DIRTY_PAGES_PER_CALL_MAX)
		nr = DIRTY_PAGES_PER_CALL_MAX;
	return nr;
}

static void dirty_whole_mapping(struct map *map)
{
	unsigned int i, nr;

	if (mark_map_rw(map) == false)
		return;

	nr = dirty_walk_count(map);

	for (i = 0; i < nr; i++) {
		char *p = map->ptr + (i * page_size);
		*p = rand();
	}
}

static void dirty_every_other_page(struct map *map)
{
	unsigned int i, walk, total, first;

	total = nr_pages(map);
	walk = dirty_walk_count(map);
	first = RAND_BOOL();

	/* Step by 2, but stop after `walk` iterations rather than after
	 * `total` pages, so we cap the per-call mprotect count.  walk*2
	 * <= total*2 so the index never overruns. */
	for (i = 0; i < walk; i++) {
		unsigned int idx = first + (i * 2);

		if (idx >= total)
			break;
		char *p = map->ptr + (idx * page_size);
		if (mark_page_rw(p) == true)
			*p = rand();
	}
}

static void dirty_mapping_reverse(struct map *map)
{
	unsigned int i, walk, total;

	total = nr_pages(map);
	if (total == 0)
		return;

	walk = dirty_walk_count(map);

	/* Walk the topmost `walk` pages, descending. */
	for (i = 0; i < walk; i++) {
		unsigned int idx = total - 1 - i;
		char *p = map->ptr + (idx * page_size);

		if (mark_page_rw(p) == true)
			*p = rand();
	}
}

/* dirty a random set of map->size pages. (some may be faulted >once) */
static void dirty_random_pages(struct map *map)
{
	unsigned int i, walk, total;

	total = nr_pages(map);
	if (total == 0)
		return;

	walk = dirty_walk_count(map);

	for (i = 0; i < walk; i++) {
		/* Offset is uniform across the FULL mapping; only the
		 * iteration count is capped.  Preserves the
		 * "any page in the mapping" sampling distribution. */
		off_t offset = (rand() % total) * page_size;
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
