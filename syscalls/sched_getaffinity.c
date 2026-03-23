/*
 * SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
	 unsigned long __user *, user_mask_ptr)
 */
#include <sched.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_sched_getaffinity(struct syscallrecord *rec)
{
	cpu_set_t *mask;

	mask = (cpu_set_t *) get_writable_address(sizeof(*mask));

	/* len must be at least sizeof(cpumask_t) for success, but exercise
	 * various sizes including too-small for error paths. */
	switch (rand() % 4) {
	case 0: rec->a2 = sizeof(*mask); break;
	case 1: rec->a2 = 4; break;		/* too small on most systems */
	case 2: rec->a2 = 8; break;		/* might work on small systems */
	default: rec->a2 = sizeof(*mask) * 2; break;	/* oversized */
	}

	rec->a3 = (unsigned long) mask;
}

struct syscallentry syscall_sched_getaffinity = {
	.name = "sched_getaffinity",
	.group = GROUP_SCHED,
	.num_args = 3,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "len",
	.arg3name = "user_mask_ptr",
	.sanitise = sanitise_sched_getaffinity,
};
