/*
 * SYSCALL_DEFINE1(timer_delete, timer_t, timer_id)
 */
#include <stdint.h>
#include "sanitise.h"

/*
 * Precondition: timer_id (a1) must reference a kernel-allocated
 * k_itimer or timer_delete short-circuits with -EINVAL inside
 * posix_timer_get_by_id() before the productive free path runs.
 * gen_arg_timerid returns a value from OBJ_TIMERID when the pool has
 * entries, otherwise a random small int from get_random_timerid()'s
 * pool-empty fallback that almost never matches a live id.  Seed one
 * inline so timer_delete reaches the real posix_timer_delete /
 * itimer_delete teardown on the very first call in the child.
 *
 * Unlike timer_gettime, timer_delete is destructive: the fuzzed call
 * leaves the OBJ_TIMERID pool entry referencing a now-deleted id, so
 * later draws from a populated pool may hit -EINVAL on the cold
 * lookup path.  Seeding stays gated on objects_pool_empty() inside
 * seed_timerid_if_empty(), so a populated pool is never over-minted.
 * Stale-id re-delete at child teardown is harmless: the per-child
 * pool destructor (timerid_destructor in timer_create.c) issues a
 * raw glibc timer_delete() and ignores the return -- a recycled or
 * already-deleted id resolves to -EINVAL inside the timer table
 * lookup and the destructor walks on without latching any state.
 */
static void sanitise_timer_delete(struct syscallrecord *rec)
{
	int32_t tid;

	tid = seed_timerid_if_empty();
	if (tid >= 0)
		rec->a1 = (unsigned long) tid;
}

struct syscallentry syscall_timer_delete = {
	.name = "timer_delete",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_TIMERID },
	.argname = { [0] = "timer_id" },
	.sanitise = sanitise_timer_delete,
	.rettype = RET_ZERO_SUCCESS,
};
