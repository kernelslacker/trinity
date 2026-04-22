/*
 * SYSCALL_DEFINE3(sched_getattr, pid_t, pid, struct sched_attr __user *, uattr, unsigned int, size)
 */
#include <stdlib.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#define SCHED_ATTR_SIZE_VER0	48

#ifndef SCHED_GETATTR_FLAG_DL_DYNAMIC
#define SCHED_GETATTR_FLAG_DL_DYNAMIC	0x01
#endif

static unsigned long sched_getattr_flags[] = {
	0, SCHED_GETATTR_FLAG_DL_DYNAMIC,
};

static void sanitise_sched_getattr(struct syscallrecord *rec)
{
	unsigned long range = page_size - SCHED_ATTR_SIZE_VER0;

	rec->a3 = (rand() % range) + SCHED_ATTR_SIZE_VER0;
	avoid_shared_buffer(&rec->a2, rec->a3);
}

struct syscallentry syscall_sched_getattr = {
	.name = "sched_getattr",
	.group = GROUP_SCHED,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN, [3] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "param", [2] = "size", [3] = "flags" },
	.arg_params[3].list = ARGLIST(sched_getattr_flags),
	.sanitise = sanitise_sched_getattr,
};
