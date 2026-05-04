/*
 * SYSCALL_DEFINE2(nanosleep, struct timespec __user *, rqtp, struct timespec __user *, rmtp)
 */
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void post_nanosleep(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret != 0 && ret != -1L) {
		output(0, "post_nanosleep: rejected retval %ld outside {0, -1}\n", ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_nanosleep = {
	.name = "nanosleep",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "rqtp", [1] = "rmtp" },
	.post = post_nanosleep,
	.flags = AVOID_SYSCALL, // Boring.  Can cause long sleeps.
};
