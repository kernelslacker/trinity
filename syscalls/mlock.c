/*
 * SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
 */
#include <stdbool.h>
#include <stdlib.h>
#include "arch.h"
#include "maps.h"
#include "mlock-state.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_mlock(struct syscallrecord *rec)
{
	struct map *map;
	unsigned long len;
	bool over_end;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;
	if (map->size < page_size)
		return;

	rec->a1 = mlock_state_pick_start(map);
	len = mlock_state_pick_length(map->size, &over_end);
	if (!over_end)
		len = mlock_state_clamp_len(len);
	rec->a2 = len;
}

static void post_mlock(struct syscallrecord *rec)
{
	if (rec->retval != 0)
		return;
	mlock_state_record_locked(rec->a1, rec->a2);
}

struct syscallentry syscall_mlock = {
	.name = "mlock",
	.num_args = 2,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len" },
	.group = GROUP_VM,
	.sanitise = sanitise_mlock,
	.post = post_mlock,
	.rettype = RET_ZERO_SUCCESS,
};

/*
 * SYSCALL_DEFINE3(mlock2, unsigned long, start, size_t, len, int, flags)
 */

static unsigned long mlock2_flags[] = { MLOCK_ONFAULT };

struct syscallentry syscall_mlock2 = {
	.name = "mlock2",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_LIST },
	.argname = { [0] = "start", [1] = "len", [2] = "flags" },
	.arg_params[2].list = ARGLIST(mlock2_flags),
	.group = GROUP_VM,
	.sanitise = sanitise_mlock,
	.post = post_mlock,
	.rettype = RET_ZERO_SUCCESS,
};
