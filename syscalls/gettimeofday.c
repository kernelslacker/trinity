/*
 * SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv, struct timezone __user *, tz)
 */
#include <sys/time.h>
#include "sanitise.h"

static void sanitise_gettimeofday(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct timeval));
	avoid_shared_buffer(&rec->a2, sizeof(struct timezone));
}

struct syscallentry syscall_gettimeofday = {
	.name = "gettimeofday",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "tv", [1] = "tz" },
	.sanitise = sanitise_gettimeofday,
	.rettype = RET_ZERO_SUCCESS,
};
