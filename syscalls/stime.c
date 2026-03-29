/*
 * SYSCALL_DEFINE1(stime, time_t __user *, tptr)
 */
#include <time.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_stime(struct syscallrecord *rec)
{
	time_t *t;

	t = (time_t *) get_writable_address(sizeof(*t));

	switch (rand() % 3) {
	case 0:	/* near current time */
		*t = time(NULL) + (rand() % 120) - 60;
		break;
	case 1:	/* epoch */
		*t = 0;
		break;
	default:
		*t = (time_t) rand32();
		break;
	}

	rec->a1 = (unsigned long) t;
}

struct syscallentry syscall_stime = {
	.name = "stime",
	.group = GROUP_TIME,
	.num_args = 1,
	.argname = { [0] = "tptr" },
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_stime,
};
