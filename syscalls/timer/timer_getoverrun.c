/*
 * SYSCALL_DEFINE1(timer_getoverrun, timer_t, timer_id)
 */
#include <limits.h>
#include <stdint.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Precondition: timer_id (a1) must reference a kernel-allocated
 * k_itimer or timer_getoverrun short-circuits with -EINVAL inside
 * posix_timer_get_by_id() before the overrun-count read runs.
 * gen_arg_timerid returns a value from OBJ_TIMERID when the pool has
 * entries, otherwise a random small int from get_random_timerid()'s
 * pool-empty fallback that almost never matches a live id.  Seed one
 * inline so timer_getoverrun reaches the productive kernel path on
 * the very first call in the child.
 */
static void sanitise_timer_getoverrun(struct syscallrecord *rec)
{
	int32_t tid;

	tid = seed_timerid_if_empty();
	if (tid >= 0)
		rec->a1 = (unsigned long) tid;
}

static void post_timer_getoverrun(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	if (ret < 0 || ret > INT_MAX) {
		output(0, "timer_getoverrun oracle: returned %ld is out of range (must be 0..INT_MAX or -1)\n",
			ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_timer_getoverrun = {
	.name = "timer_getoverrun",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_TIMERID },
	.argname = { [0] = "timer_id" },
	.sanitise = sanitise_timer_getoverrun,
	.post = post_timer_getoverrun,
	.rettype = RET_BORING,
};
