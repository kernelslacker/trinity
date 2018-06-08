/*
 * SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len, unsigned char __user *, vec)
 */
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_mincore(struct syscallrecord *rec)
{
	struct map *map;
	unsigned long len;

	map = common_set_mmap_ptr_len();

	len = min(GB(1), map->size);
	len = len + (page_size - 1) / page_size;

	rec->a3 = (unsigned long) zmalloc(len);	// FIXME: LEAK
}

static void post_mincore(struct syscallrecord *rec)
{
	freeptr(&rec->a3);
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
