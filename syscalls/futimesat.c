/*
 * SYSCALL_DEFINE3(futimesat, int, dfd, const char __user *, filename,
	 struct timeval __user *, utimes)
 */
#include <sys/time.h>
#include "random.h"
#include "sanitise.h"

static void sanitise_futimesat(struct syscallrecord *rec)
{
	struct timeval *tv;
	unsigned int i;

	/* NULL utimes means "set both to current time" - allow that sometimes */
	if (ONE_IN(8)) {
		rec->a3 = 0;
		return;
	}

	tv = (struct timeval *) get_writable_address(sizeof(*tv) * 2);

	for (i = 0; i < 2; i++) {
		tv[i].tv_sec = rand() % 2000000000;
		tv[i].tv_usec = rand() % 1000000;
	}

	rec->a3 = (unsigned long) tv;
}

struct syscallentry syscall_futimesat = {
	.name = "futimesat",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_ADDRESS },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "utimes" },
	.sanitise = sanitise_futimesat,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
};
