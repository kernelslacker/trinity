/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */
#include <asm/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

static void sanitise_mprotect(int childno)
{
	(void) common_set_mmap_ptr_len(childno);
}

/*
 * If we successfully did an mprotect, update our record of the mappings prot bits.
 */
static void post_mprotect(int childno)
{
	struct map *map = (struct map *) shm->scratch[childno];

	if (shm->syscall[childno].retval != 0)
		map->prot = shm->syscall[childno].a3;

	shm->scratch[childno] = 0;
}

struct syscallentry syscall_mprotect = {
	.name = "mprotect",
	.num_args = 3,
	.arg1name = "start",
	.arg1type = ARG_MMAP,
	.arg2name = "len",
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 6,
		.values = { PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM, PROT_GROWSDOWN, PROT_GROWSUP },
	},
	.sanitise = sanitise_mprotect,
	.group = GROUP_VM,
	.post = post_mprotect,
};
