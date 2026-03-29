/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */
#include <asm/mman.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static void sanitise_mprotect(struct syscallrecord *rec)
{
	struct map *map = common_set_mmap_ptr_len();

	if (range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a1 = 0;
		rec->a2 = 0;
	}

	/* Stash map pointer in unused arg slot for post callback. */
	rec->a5 = (unsigned long) map;
}

/*
 * If we successfully did an mprotect, update our record of the mappings prot bits.
 */
static void post_mprotect(struct syscallrecord *rec)
{
	struct map *map = (struct map *) rec->a5;

	if (rec->retval == 0)
		map->prot = rec->a3;
}

static unsigned long mprotect_prots[] = {
	PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM,
	PROT_GROWSDOWN, PROT_GROWSUP,
};

struct syscallentry syscall_mprotect = {
	.name = "mprotect",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "start", [1] = "len", [2] = "prot" },
	.arg3list = ARGLIST(mprotect_prots),
	.sanitise = sanitise_mprotect,
	.group = GROUP_VM,
	.post = post_mprotect,
};

struct syscallentry syscall_pkey_mprotect = {
	.name = "pkey_mprotect",
	.num_args = 4,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "start", [1] = "len", [2] = "prot", [3] = "key" },
	.arg3list = ARGLIST(mprotect_prots),
	.sanitise = sanitise_mprotect,
	.group = GROUP_VM,
	.post = post_mprotect,
};
