/*
 * SYSCALL_DEFINE2(sched_getparam, pid_t, pid, struct sched_param __user *, param)
 */
#include <sched.h>
#include "sanitise.h"

static void sanitise_sched_getparam(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct sched_param));
}

struct syscallentry syscall_sched_getparam = {
	.name = "sched_getparam",
	.group = GROUP_SCHED,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "pid", [1] = "param" },
	.sanitise = sanitise_sched_getparam,
	.rettype = RET_ZERO_SUCCESS,
};
