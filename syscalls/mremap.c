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
#include "syscall.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static struct map *map;

static const unsigned long alignments[] = {
	MB(1), MB(2), MB(4), MB(4),
	MB(10), MB(100),
	GB(1), GB(2), GB(4),
};

static void sanitise_mremap(struct syscallrecord *rec)
{
	unsigned long newaddr = 0;

	map = common_set_mmap_ptr_len();

	rec->a3 = map->size;		//TODO: Munge this.

	if (rec->a4 & MREMAP_FIXED) {
		unsigned long align = RAND_ARRAY(alignments);
		unsigned int shift = (WORD_BIT / 2) - 1;

		newaddr = RAND_BYTE();
		newaddr <<= shift;
		newaddr |= align;
		newaddr &= ~(align - 1);
	}

	rec->a5 = newaddr;
}

/*
 * If we successfully remapped a range, we need to update our record of it
 * so we don't re-use the old address.
 */
static void post_mremap(struct syscallrecord *rec)
{
	void *ptr = (void *) rec->retval;

	if (ptr == MAP_FAILED)
		return;

	map->ptr = ptr;

	/* Sometimes dirty the mapping first. */
//	if (RAND_BOOL())
//		dirty_mapping(map);
}

static unsigned long mremap_flags[] = {
	MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP,
};

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
	.arg4list = ARGLIST(mremap_flags),
	.arg5name = "new_addr",
	.group = GROUP_VM,
	.post = post_mremap,
};
