/*
 * SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid, unsigned int, len,
	 unsigned long __user *, user_mask_ptr)
 */
#include <sched.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_sched_setaffinity(struct syscallrecord *rec)
{
	cpu_set_t *mask;
	unsigned int i, ncpus;

	mask = (cpu_set_t *) get_writable_struct(sizeof(*mask));
	if (!mask)
		return;
	CPU_ZERO(mask);

	switch (rand() % 4) {
	case 0: /* single CPU */
		CPU_SET(rand() % CPU_SETSIZE, mask);
		break;
	case 1: /* first N CPUs (small, realistic) */
		ncpus = 1 + (rand() % 8);
		for (i = 0; i < ncpus; i++)
			CPU_SET(i, mask);
		break;
	case 2: /* all CPUs set */
		for (i = 0; i < CPU_SETSIZE; i++)
			CPU_SET(i, mask);
		break;
	default: /* random sparse mask */
		ncpus = 1 + (rand() % 16);
		for (i = 0; i < ncpus; i++)
			CPU_SET(rand() % CPU_SETSIZE, mask);
		break;
	}

	rec->a2 = sizeof(*mask);
	rec->a3 = (unsigned long) mask;
}

struct syscallentry syscall_sched_setaffinity = {
	.name = "sched_setaffinity",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "len", [2] = "user_mask_ptr" },
	.sanitise = sanitise_sched_setaffinity,
};
