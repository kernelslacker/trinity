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
#include "trinity.h"

static void sanitise_remap_file_pages(__unused__ int childno, struct syscallrecord *rec)
{
	struct map *map;
	size_t size;

	map = common_set_mmap_ptr_len();

	/* We just want to remap a part of the mapping. */
	size = rand() % map->size;
	rec->a2 = size;

	/* "The prot argument must be specified as 0" */
	rec->a3 = 0;

	/* Pick a random pgoff. */
	rec->a4 = rand() & (size / page_size);
}

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
	.arg5list = {
		.num = 1,
		.values = { MAP_NONBLOCK },
	},
	.group = GROUP_VM,
	.sanitise = sanitise_remap_file_pages,
};
