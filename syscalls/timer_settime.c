/*
 * SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
	const struct itimerspec __user *, new_setting,
	struct itimerspec __user *, old_setting)
 */
#include <time.h>
#include "random.h"
#include "sanitise.h"

/*
 * new_setting (a3) is typed ARG_ITIMERSPEC; the generator publishes a
 * writable pool buffer (or NULL ~10%) and owns the bucketed it_value /
 * it_interval fill -- including the near-now (time(NULL)+1) bucket that
 * keeps a TIMER_ABSTIME deadline in the future.  The generator only
 * fills the struct though; the sibling flags arg (a2) lives here, so
 * keep a small stub that still picks TIMER_ABSTIME a fraction of the
 * time so the kernel's absolute-deadline path stays reachable.
 *
 * old_setting (a4) keeps ARG_ADDRESS + avoid_shared_buffer_out so the
 * kernel writeback never lands in the shared region.
 */
static void sanitise_timer_settime(struct syscallrecord *rec)
{
	rec->a2 = 0;
	if (ONE_IN(5))
		rec->a2 = TIMER_ABSTIME;

	avoid_shared_buffer_out(&rec->a4, sizeof(struct itimerspec));
}

struct syscallentry syscall_timer_settime = {
	.name = "timer_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_TIMERID, [2] = ARG_ITIMERSPEC, [3] = ARG_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "flags", [2] = "new_setting", [3] = "old_setting" },
	.sanitise = sanitise_timer_settime,
	.rettype = RET_ZERO_SUCCESS,
};
