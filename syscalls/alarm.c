/*
 * SYSCALL_DEFINE1(alarm, unsigned int, seconds)
 *
 * returns  the number of seconds remaining until any previously scheduled alarm was due to be delivered,
 *  or zero if there was no previously scheduled
 */
#include <limits.h>
#include "deferred-free.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the seconds input arg read by the prev-bound oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->a1 between the syscall returning and the post
 * handler running cannot raise the bound and silently launder a wild
 * remaining-seconds retval past the prev-bound check.
 */
struct alarm_post_state {
	unsigned int seconds;
};

static void sanitise_alarm(struct syscallrecord *rec)
{
	struct alarm_post_state *snap;

	rec->post_state = 0;

	snap = zmalloc(sizeof(*snap));
	snap->seconds = (unsigned int) rec->a1;
	rec->post_state = (unsigned long) snap;
}

/*
 * alarm_setitimer() clamps the input to INT_MAX before arming, so the
 * remaining-seconds value the kernel returns cannot legitimately exceed
 * INT_MAX. A retval in (INT_MAX, UINT_MAX] therefore implies a
 * sign-extension or 32-on-64 copy-out tear in the syscall return path.
 * The kernel has no normal failure path for this call, so -1UL is the
 * other smoking-gun shape worth catching — but we filter it out here
 * because the bug-detection signal lives in the high-bits-set value.
 *
 * Prev-bound extension: the kernel returns the seconds remaining of any
 * *previously* scheduled alarm, which can never exceed the prior alarm's
 * setting.  The seconds input is snapshotted at sanitise time into
 * rec->post_state so a sibling scribbling rec->a1 between syscall return
 * and post entry cannot raise the bound and launder a wild retval past
 * the prev-bound check.
 */
static void post_alarm(struct syscallrecord *rec)
{
	unsigned long retval = (unsigned long) rec->retval;
	struct alarm_post_state *snap;

	if (retval > (unsigned long) INT_MAX && retval != (unsigned long)-1L) {
		output(0, "post_alarm: rejected retval 0x%lx outside [0, INT_MAX] (and not -1)\n",
		       retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	snap = (struct alarm_post_state *) rec->post_state;
	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_alarm: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (retval != (unsigned long)-1L && (long) retval > (long) snap->seconds) {
		output(0, "post_alarm: rejected retval %lu exceeds prior alarm bound %u\n",
		       retval, snap->seconds);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

out_free:
	deferred_freeptr(&rec->post_state);
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
	.sanitise = sanitise_alarm,
	.post = post_alarm,
};
