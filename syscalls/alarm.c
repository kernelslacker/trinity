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
 * Snapshot of the seconds input arg read by the prev-bound oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->a1 between the syscall returning and the post
 * handler running cannot raise the bound and silently launder a wild
 * remaining-seconds retval past the prev-bound check.
 */
#define ALARM_POST_STATE_MAGIC	0x414C524DUL	/* "ALRM" */
struct alarm_post_state {
	unsigned long magic;
	unsigned int seconds;
};

static void sanitise_alarm(struct syscallrecord *rec)
{
	struct alarm_post_state *snap;

	rec->post_state = 0;

	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_alarm() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic   = ALARM_POST_STATE_MAGIC;
	snap->seconds = (unsigned int) rec->a1;
	post_state_install(rec, snap);
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

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, ALARM_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if (retval != (unsigned long)-1L && (long) retval > (long) snap->seconds) {
		output(0, "post_alarm: rejected retval %lu exceeds prior alarm bound %u\n",
		       retval, snap->seconds);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	post_state_release(rec, snap);
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
	.rettype = RET_BORING,
};
