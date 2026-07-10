/*
 * SYSCALL_DEFINE0(munlockall)
 */
#include <sys/mman.h>
#include "arch.h"
#include "maps.h"
#include "mlock-state.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

static void sanitise_munlockall(struct syscallrecord *rec __unused__)
{
	struct map *map;

	/*
	 * munlockall takes no args, so the picker draws an identical
	 * call shape every time.  When nothing is currently locked the
	 * kernel walks an empty per-mm VM_LOCKED list and returns 0
	 * without ever touching apply_mlockall_flags's per-vma unlock
	 * leg -- "high calls, low edges" cold-syscall shape that the
	 * wall-lever shadow gate keeps re-flagging.  Plant a single-page
	 * mlock on a random map ~50% of the time so the upcoming
	 * munlockall finds a locked vma to walk through; the other half
	 * preserves the empty-list fast-path arm so both stay exercised.
	 *
	 * Coverage-only side effect: a failed plant (EAGAIN under the
	 * memlock cap, ENOMEM on an unmapped slot left in the pool by a
	 * sibling munmap) collapses harmlessly back to the empty-list
	 * shape we would otherwise have had.
	 */
	if (rnd_modulo_u32(2) != 0)
		return;

	map = get_map();
	if (map == NULL || map->size < page_size)
		return;

	if (mlock(map->ptr, page_size) == 0)
		mlock_state_record_locked((unsigned long) map->ptr, page_size);
}

static void post_munlockall(struct syscallrecord *rec)
{
	if (rec->retval != 0)
		return;
	mlock_state_reset();
}

struct syscallentry syscall_munlockall = {
	.name = "munlockall",
	.num_args = 0,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VM,
	.sanitise = sanitise_munlockall,
	.post = post_munlockall,
};
