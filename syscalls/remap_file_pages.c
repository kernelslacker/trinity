/*
 * SYSCALL_DEFINE5(remap_file_pages, unsigned long, start, unsigned long, size,
	 unsigned long, prot, unsigned long, pgoff, unsigned long, flags)
 */
#include <stdlib.h>
#include <asm/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"

static void sanitise_remap_file_pages(struct syscallrecord *rec)
{
	struct map *map;
	size_t size, offset;
	size_t start = 0;

	map = common_set_mmap_ptr_len();

	if (RAND_BOOL()) {
		start = rnd() % map->size;
		start &= PAGE_MASK;
		rec->a1 += start;
	}

	/* We just want to remap a part of the mapping. */
	if (RAND_BOOL())
		size = page_size;
	else {
		size = rnd() % map->size;

		/* if we screwed with the start, we need to take it
		 * into account so we don't go off the end.
		 */
		if (start != 0)
			size -= start;
	}
	rec->a2 = size;

	/* "The prot argument must be specified as 0" */
	rec->a3 = 0;

	/* Pick a random pgoff. */
	if (RAND_BOOL())
		offset = rnd() & (size / page_size);
	else
		offset = 0;
	rec->a4 = offset;
}

static unsigned long remap_file_pages_flags[] = {
	MAP_NONBLOCK,
};

struct syscallentry syscall_remap_file_pages = {
	.name = "remap_file_pages",
	.num_args = 5,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "size",
	.arg3name = "prot",
	.arg4name = "pgoff",
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(remap_file_pages_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_remap_file_pages,
};
