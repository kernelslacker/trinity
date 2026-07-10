/*
 * SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
 */
#include <stdbool.h>
#include "arch.h"
#include "maps.h"
#include "mlock-state.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/*
 * Draw a page-aligned subset of a recently-locked (start, len) range
 * so the kernel's vma walk has a real chance of finding a locked vma
 * to unlock.  The subset shape is uniform across "full range",
 * "trailing tail", and "interior window" so munlock exercises both
 * whole-range fast paths and the split-vma slow path.
 */
static void pick_recent_subset(unsigned long parent_start,
			       unsigned long parent_len,
			       unsigned long *startp,
			       unsigned long *lenp)
{
	unsigned long pages = parent_len / page_size;
	unsigned long off_pages;
	unsigned long sub_pages;

	if (pages < 2) {
		*startp = parent_start;
		*lenp = parent_len;
		return;
	}
	off_pages = rnd_modulo_u32((uint32_t) pages);
	sub_pages = 1 + rnd_modulo_u32((uint32_t) (pages - off_pages));
	*startp = parent_start + off_pages * (unsigned long) page_size;
	*lenp = sub_pages * (unsigned long) page_size;
}

static void sanitise_munlock(struct syscallrecord *rec)
{
	struct map *map;
	unsigned long start, len;
	bool over_end;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;
	if (map->size < page_size)
		return;

	if ((rnd_modulo_u32(2) == 0) &&
	    mlock_state_pick_recent(&start, &len)) {
		pick_recent_subset(start, len, &start, &len);
	} else {
		start = mlock_state_pick_start(map);
		len = mlock_state_pick_length(map->size, &over_end);
	}

	rec->a1 = start;
	rec->a2 = len;
}

static void post_munlock(struct syscallrecord *rec)
{
	if (rec->retval != 0)
		return;
	mlock_state_record_unlocked(rec->a2);
}

struct syscallentry syscall_munlock = {
	.name = "munlock",
	.num_args = 2,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_munlock,
	.post = post_munlock,
};
