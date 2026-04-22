/*
 * SYSCALL_DEFINE1(times, struct tms __user *, tbuf)
 */
#include <sys/times.h>
#include "sanitise.h"

static void sanitise_times(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct tms));
}

struct syscallentry syscall_times = {
	.name = "times",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tbuf" },
	.sanitise = sanitise_times,
};
