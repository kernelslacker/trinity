/*
 * SYSCALL_DEFINE3(mincore, unsigned long, start, size_t, len, unsigned char __user *, vec)
 */
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_mincore(struct syscallrecord *rec)
{
	struct map *map;
	unsigned long len;
	void *vec;

	map = common_set_mmap_ptr_len();

	len = min(GB(1), map->size);
	len = (len + page_size - 1) / page_size;

	vec = zmalloc(len);
	rec->a3 = (unsigned long) vec;
	/* Snapshot for the post handler -- a3 may be scribbled by a sibling
	 * syscall before post_mincore() runs. */
	rec->post_state = (unsigned long) vec;
}

static void post_mincore(struct syscallrecord *rec)
{
	void *vec = (void *) rec->post_state;

	if (vec == NULL)
		return;

	if (looks_like_corrupted_ptr(vec)) {
		outputerr("post_mincore: rejected suspicious vec=%p (pid-scribbled?)\n", vec);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a3 = 0;
	deferred_freeptr(&rec->post_state);
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
