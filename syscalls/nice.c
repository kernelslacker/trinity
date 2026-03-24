/*
 * SYSCALL_DEFINE1(nice, int, increment)
 */
#include "random.h"
#include "sanitise.h"

static void sanitise_nice(struct syscallrecord *rec)
{
	rec->a1 = (unsigned long)((rand() % 40) - 20);	/* -20 to 19 */
}

struct syscallentry syscall_nice = {
	.name = "nice",
	.num_args = 1,
	.arg1name = "increment",
	.sanitise = sanitise_nice,
	.group = GROUP_SCHED,
};
