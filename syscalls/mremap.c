/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 */
#include <linux/mman.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "utils.h"	// page_size
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static unsigned long rand_size(void)
{
	const unsigned long sizes[] = { 1 * MB, 2 * MB, 4 * MB, 10 * MB, 1 * GB, 2 * GB };

	return sizes[rand() % ARRAY_SIZE(sizes)];
}

static void sanitise_mremap(int childno)
{
	struct map *map;

	map = common_set_mmap_ptr_len(childno);

	shm->a3[childno] = map->size;		//TODO: Munge this.

	if (shm->a4[childno] & MREMAP_FIXED) {
		shm->a5[childno] = rand_size();
	} else {
		shm->a5[childno] = 0;
	}

	/* Sometimes dirty the mapping first. */
	if (!(map->prot & PROT_WRITE))
		return;

	if (rand_bool())
		dirty_mapping(map);
}

/*
 * If we successfully remapped a range, we need to update our record of it
 * so we don't re-use the old address.
 */
static void post_mremap(int childno)
{
	struct map *map = (struct map *) shm->scratch[childno];
	void *ptr = (void *) shm->retval[childno];

	if (ptr != MAP_FAILED)
		map->ptr = ptr;

	shm->scratch[childno] = 0;
}

struct syscallentry syscall_mremap = {
	.name = "mremap",
	.num_args = 5,
	.sanitise = sanitise_mremap,
	.arg1name = "addr",
	.arg1type = ARG_MMAP,
	.arg2name = "old_len",
	.arg3name = "new_len",
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 2,
		.values = { MREMAP_MAYMOVE, MREMAP_FIXED },
	},
	.arg5name = "new_addr",
	.arg5type = ARG_ADDRESS,
	.group = GROUP_VM,
	.post = post_mremap,
};
