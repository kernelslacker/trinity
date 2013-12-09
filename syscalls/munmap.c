/*
 * SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
 */
#include "maps.h"
#include "sanitise.h"
#include "shm.h"

static void sanitise_munmap(int childno)
{
	(void) common_set_mmap_ptr_len(childno);
}

static void post_munmap(int childno)
{
	struct map *map = (struct map *) shm->scratch[childno];

	if (shm->retval[childno] != 0)
		return;

	// TODO: Should we only allow un-munmaping local mmaps?
	delete_local_mapping(childno, map);
}

struct syscall syscall_munmap = {
	.name = "munmap",
	.num_args = 2,
	.arg1name = "addr",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.group = GROUP_VM,
	.sanitise = sanitise_munmap,
	.post = post_munmap,
};
