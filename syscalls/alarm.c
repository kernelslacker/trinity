/*
 * SYSCALL_DEFINE1(alarm, unsigned int, seconds)
 *
 * returns  the number of seconds remaining until any previously scheduled alarm was due to be delivered,
 *  or zero if there was no previously scheduled
 */
#include <limits.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * alarm_setitimer() clamps the input to INT_MAX before arming, so the
 * remaining-seconds value the kernel returns cannot legitimately exceed
 * INT_MAX. A retval in (INT_MAX, UINT_MAX] therefore implies a
 * sign-extension or 32-on-64 copy-out tear in the syscall return path.
 * The kernel has no normal failure path for this call, so -1UL is the
 * other smoking-gun shape worth catching — but we filter it out here
 * because the bug-detection signal lives in the high-bits-set value.
 */
static void post_alarm(struct syscallrecord *rec)
{
	unsigned long retval = (unsigned long) rec->retval;

	if (retval > (unsigned long) INT_MAX && retval != (unsigned long)-1L) {
		output(0, "post_alarm: rejected retval 0x%lx outside [0, INT_MAX] (and not -1)\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_alarm = {
	.flags = AVOID_SYSCALL,	/* we rely on a useful alarm for every syscall. */
	.name = "alarm",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "seconds" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 5,
	.post = post_alarm,
};
