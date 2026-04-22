/*
 * SYSCALL_DEFINE1(time, time_t __user *, tloc)
 */
#include <time.h>
#include "sanitise.h"

static void sanitise_time(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(time_t));
}

struct syscallentry syscall_time = {
	.name = "time",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tloc" },
	.sanitise = sanitise_time,
};
