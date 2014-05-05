/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 */

#include <stdlib.h>
#include <sys/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static void sanitise_mremap(int childno)
{
	struct map *map;

	map = common_set_mmap_ptr_len(childno);

	shm->syscall[childno].a3 = map->size;		//TODO: Munge this.

	if (shm->syscall[childno].a4 & MREMAP_FIXED) {
		shm->syscall[childno].a5 = ((rand() % 256) << (rand() % __WORDSIZE));
		shm->syscall[childno].a5 += page_size;
		shm->syscall[childno].a5 &= PAGE_MASK;
	} else {
		shm->syscall[childno].a5 = 0;
	}
}

/*
 * If we successfully remapped a range, we need to update our record of it
 * so we don't re-use the old address.
 */
static void post_mremap(int childno)
{
	struct map *map = (struct map *) shm->scratch[childno];
	void *ptr = (void *) shm->syscall[childno].retval;

	if (ptr == MAP_FAILED)
		return;

	map->ptr = ptr;

	shm->scratch[childno] = 0;

	/* Sometimes dirty the mapping first. */
	if (rand_bool())
		dirty_mapping(map);
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
	.group = GROUP_VM,
	.post = post_mremap,
};
