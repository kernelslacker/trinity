/*
 * SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len, unsigned char __user *, vec)
 */
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_mincore(int childno)
{
	struct map *map;
	unsigned long len;

	map = common_set_mmap_ptr_len(childno);

	len = map->size + (page_size - 1) / page_size;
	shm->a3[childno] = (unsigned long) malloc(len);
}

static void post_mincore(int childno)
{
	free((void *) shm->a3[childno]);
}

struct syscallentry syscall_mincore = {
	.name = "mincore",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg3name = "vec",
	.group = GROUP_VM,
	.sanitise = sanitise_mincore,
	.post = post_mincore,
};
