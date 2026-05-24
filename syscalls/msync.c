/*
 * SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
 */
#include <stdlib.h>
#include "maps.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#if !defined(MS_ASYNC)
#define MS_ASYNC        1               /* Sync memory asynchronously.  */
#endif
#if !defined(MS_SYNC)
#define MS_SYNC         4               /* Synchronous memory sync.  */
#endif
#if !defined(MS_INVALIDATE)
#define MS_INVALIDATE   2               /* Invalidate the caches.  */
#endif

/*
 * msync's flags slot used to come from ARG_OP over { MS_ASYNC,
 * MS_SYNC } plus an unconditional `if (RAND_BOOL()) rec->a3 |=
 * MS_INVALIDATE;` OR-in.  Two problems with that arrangement:
 *
 *  - ARG_OP's cmp-hint injection path occasionally returns a value
 *    that already has both MS_ASYNC and MS_SYNC set, and ORing
 *    MS_INVALIDATE on top still leaves the mutually-exclusive
 *    MS_ASYNC|MS_SYNC pair the kernel rejects with EINVAL before
 *    ever entering the writeback path.
 *
 *  - Even on the well-formed draws the MS_INVALIDATE-vs-not split
 *    was implicit, so the four documented shapes (async, sync, async
 *    + invalidate, sync + invalidate) were not exercised at known
 *    proportions and a regression that quietly stopped covering one
 *    of them would be invisible from the outside.
 *
 * Drive the slot from explicit buckets here so the success-path
 * shapes have known proportions, then keep a small (10%) bucket
 * that intentionally hands the kernel MS_ASYNC|MS_SYNC so the
 * argument-validation EINVAL path still sees traffic without being
 * the dominant outcome.
 */
static unsigned long pick_msync_flags(void)
{
	unsigned int r = rnd_modulo_u32(100);

	if (r < 30)
		return MS_ASYNC;
	if (r < 60)
		return MS_SYNC;
	if (r < 75)
		return MS_ASYNC | MS_INVALIDATE;
	if (r < 90)
		return MS_SYNC | MS_INVALIDATE;
	return MS_ASYNC | MS_SYNC;
}

static void sanitise_msync(struct syscallrecord *rec)
{
	struct map *map;

	map = common_set_mmap_ptr_len(NULL);
	if (map == NULL)
		return;

	rec->a3 = pick_msync_flags();
}

struct syscallentry syscall_msync = {
	.name = "msync",
	.num_args = 3,
	.argtype = { [0] = ARG_MMAP, [1] = ARG_LEN, [2] = ARG_UNDEFINED },
	.argname = { [0] = "start", [1] = "len", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VM,
	.sanitise = sanitise_msync,
};
