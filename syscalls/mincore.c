/*
 * SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len, unsigned char __user *, vec)
 */
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_mincore(struct syscallrecord *rec)
{
	struct map *map;
	unsigned long len;

	map = common_set_mmap_ptr_len();

	len = min(GB(1), map->size);
	len = (len + page_size - 1) / page_size;

	rec->a3 = (unsigned long) zmalloc(len);
}

static void post_mincore(struct syscallrecord *rec)
{
	freeptr(&rec->a3);
}

struct syscallentry syscall_mincore = {
	.name = "mincore",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_ADDRESS },
	.argname = { [0] = "start", [1] = "len", [2] = "vec" },
	.group = GROUP_VM,
	.sanitise = sanitise_mincore,
	.post = post_mincore,
};
