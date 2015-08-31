/*
 * SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
 */
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

#define WHOLE 1
static int action;

static struct map *map;

static void sanitise_munmap(struct syscallrecord *rec)
{
	map = common_set_mmap_ptr_len();

	action = 0;

	if (ONE_IN(20) == TRUE) {
		/* delete the whole mapping. */
		action = WHOLE;
		return;
	}

	if (RAND_BOOL()) {
		/* unmap a range of the mapping. */
		unsigned long nr_pages;
		unsigned long offset, offsetpagenr;
		unsigned long len;

		nr_pages = map->size / page_size;
		offsetpagenr = rand() % nr_pages;
		offset = offsetpagenr * page_size;
		rec->a1 = (unsigned long) map->ptr + offset;

		len = (rand() % (nr_pages - offsetpagenr)) + 1;
		len *= page_size;
		rec->a2 = len;
	} else {
		/* just unmap 1 page of the mapping. */

		rec->a1 = (unsigned long) map->ptr;
		rec->a1 += (rand() % map->size) & PAGE_MASK;
		rec->a2 = page_size;
	}
}

static void post_munmap(struct syscallrecord *rec)
{
	if (rec->retval != 0)
		return;

	if (action == WHOLE) {
		list_del(&map->list);
		this_child->num_mappings--;
	}
}

struct syscallentry syscall_munmap = {
	.name = "munmap",
	.num_args = 2,
	.arg1name = "addr",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.group = GROUP_VM,
	.sanitise = sanitise_munmap,
	.post = post_munmap,
};
