/*
 * SYSCALL_DEFINE2(sched_rr_get_interval, pid_t, pid, struct timespec __user *, interval)
 */
#include <time.h>
#include "sanitise.h"

static void sanitise_sched_rr_get_interval(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct timespec));
}

struct syscallentry syscall_sched_rr_get_interval = {
	.name = "sched_rr_get_interval",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "interval" },
	.sanitise = sanitise_sched_rr_get_interval,
};
