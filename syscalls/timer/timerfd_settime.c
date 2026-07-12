/*
 * SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
	 const struct itimerspec __user *, utmr,
	 struct itimerspec __user *, otmr)
 */
#include <stdint.h>
#include <sys/timerfd.h>
#include <time.h>
#include "objects.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/timerfd.h"
#ifndef TFD_TIMER_CANCEL_ON_SET
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif

/*
 * Snapshot of the timerfd_settime otmr pointer plus the poison seed
 * read by the post oracle, captured at sanitise time and consumed by
 * the post handler.  Lives in rec->post_state, a slot the syscall ABI
 * does not expose, so a sibling syscall scribbling rec->a4 between the
 * syscall returning and the post handler running cannot redirect the
 * poison check against an unrelated heap page whose residual bytes
 * happen to still match some earlier call's seed.  A poison_seed of 0
 * means the sanitise-time writability check refused to stamp poison
 * for this call (otmr is ARG_ADDRESS so a4 == 0 is a documented
 * "don't write back", or the writable draw was no longer provably
 * mapped) and the post handler must no-op the untouched-buffer arm.
 */
#define TIMERFD_SETTIME_POST_STATE_MAGIC	0x54465354UL	/* "TFST" */
struct timerfd_settime_post_state {
	unsigned long magic;
	unsigned long otmr;
	uint64_t poison_seed;
};

static void fill_nonzero_timespec(struct timespec *ts)
{
	switch (rnd_modulo_u32(4)) {
	case 0: ts->tv_sec = 0; ts->tv_nsec = 1; break;
	case 1: ts->tv_sec = 0; ts->tv_nsec = 1 + rnd_modulo_u32(1000000); break;
	case 2: ts->tv_sec = 1 + rnd_modulo_u32(10); ts->tv_nsec = rnd_modulo_u32(1000000000); break;
	default: ts->tv_sec = rand32(); ts->tv_nsec = rnd_modulo_u32(1000000000); break;
	}
}

/*
 * TFD_TIMER_CANCEL_ON_SET only has meaning when paired with
 * TFD_TIMER_ABSTIME on a CLOCK_REALTIME timerfd.  The OBJ_FD_TIMERFD
 * pool publishes the clockid each fd was created with, so look the
 * picked fd up and refuse to set the bit on monotonic/boottime fds
 * where the kernel would just return EINVAL.
 */
static int timerfd_is_realtime(int fd)
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_TIMERFD);
	if (head == NULL)
		return 0;

	for_each_obj(head, obj, idx) {
		if (obj->timerfdobj.fd != fd)
			continue;
		return obj->timerfdobj.clockid == CLOCK_REALTIME;
	}
	return 0;
}

static void sanitise_timerfd_settime(struct syscallrecord *rec)
{
	struct timerfd_settime_post_state *snap;
	struct itimerspec *its;
	uint32_t bucket;
	unsigned long flags = 0;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	its = (struct itimerspec *) get_writable_address(sizeof(*its));
	if (its == NULL)
		return;

	its->it_interval.tv_sec = 0;
	its->it_interval.tv_nsec = 0;
	its->it_value.tv_sec = 0;
	its->it_value.tv_nsec = 0;

	bucket = rnd_modulo_u32(100);
	if (bucket < 25) {
		/* disarm */
	} else if (bucket < 55) {
		/* one-shot */
		fill_nonzero_timespec(&its->it_value);
	} else if (bucket < 80) {
		/* periodic */
		fill_nonzero_timespec(&its->it_value);
		fill_nonzero_timespec(&its->it_interval);
	} else {
		/* TFD_TIMER_ABSTIME with a near-now deadline. */
		struct timespec now;

		if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
			its->it_value.tv_sec = now.tv_sec + 1;
			its->it_value.tv_nsec = now.tv_nsec;
		} else {
			fill_nonzero_timespec(&its->it_value);
		}
		flags |= TFD_TIMER_ABSTIME;
	}

	/* CANCEL_ON_SET is only valid on CLOCK_REALTIME timerfds and only
	 * paired with ABSTIME -- gate on both. */
	if ((flags & TFD_TIMER_ABSTIME) &&
	    rnd_modulo_u32(100) < 15 &&
	    timerfd_is_realtime((int) rec->a1))
		flags |= TFD_TIMER_CANCEL_ON_SET;

	rec->a2 = flags;
	rec->a3 = (unsigned long) its;
	avoid_shared_buffer_inout(&rec->a3, sizeof(struct itimerspec));
	avoid_shared_buffer_out(&rec->a4, sizeof(struct itimerspec));

	/*
	 * Snapshot the otmr pointer plus a per-call poison pattern into
	 * the user itimerspec the kernel is about to fill.  The post
	 * handler feeds the seed back into
	 * check_output_struct_user_or_skip(); a byte-identical poison
	 * after retval == 0 means the kernel skipped copy_to_user()
	 * entirely -- timerfd_settime with a non-NULL otmr contracts to
	 * write the previous timer setting there on success.  Gate on
	 * range_readable_user() which folds both the NULL gate (otmr is
	 * ARG_ADDRESS so a4 == 0 is a documented "don't write back") and
	 * the unmapped-address gate into one call: NULL and unproven
	 * ranges both return false, so poison_seed stays 0 and the post
	 * handler no-ops the untouched-buffer arm.  Done after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see (the relocation may have swapped
	 * rec->a4 for a fresh page).
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = TIMERFD_SETTIME_POST_STATE_MAGIC;
	snap->otmr  = rec->a4;
	buf = (void *)(unsigned long) rec->a4;
	if (range_readable_user(buf, sizeof(struct itimerspec)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct itimerspec),
							 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: timerfd_settime(ufd, flags, utmr, otmr) arms/disarms the
 * timerfd and, if otmr != NULL, writes the previous timer setting to
 * *otmr as a struct itimerspec.  On retval == 0 with a non-NULL otmr
 * the kernel is contracted to overwrite that struct; a byte-identical
 * poison after success means copy_to_user() was skipped entirely.
 * Bumps the shared post_handler_untouched_out_buf counter.
 *
 * Measure-only: no re-issue, no argument mutation, no oracle output
 * beyond the counter bump.  Silent on the error path (retval != 0) and
 * on the NULL-otmr path (poison_seed == 0) so no false positives.
 */
static void post_timerfd_settime(struct syscallrecord *rec)
{
	struct timerfd_settime_post_state *snap;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, TIMERFD_SETTIME_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	/*
	 * Untouched-buffer check: timerfd_settime returned 0 with a
	 * non-NULL otmr, but the itimerspec still byte-for-byte matches
	 * the poison pattern we stamped at sanitise time -- the kernel
	 * never called copy_to_user() at all.  Cheap: sizeof(struct
	 * itimerspec) memcmp, no re-issue, so runs on every success
	 * rather than under ONE_IN().  A poison_seed of 0 is the
	 * sanitise-refused-to-stamp signal (NULL otmr or unmapped
	 * writable draw) -- gating on it here also doubles as the
	 * NULL-otmr short-circuit, so no separate snap->otmr == 0 check
	 * is needed above.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->otmr,
					     sizeof(struct itimerspec),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_timerfd_settime = {
	.name = "timerfd_settime",
	.group = GROUP_TIME,
	.num_args = 4,
	.argtype = { [0] = ARG_FD_TIMERFD, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS },
	.argname = { [0] = "ufd", [1] = "flags", [2] = "utmr", [3] = "otmr" },
	.sanitise = sanitise_timerfd_settime,
	.post = post_timerfd_settime,
	.flags = NEED_ALARM,
	.rettype = RET_ZERO_SUCCESS,
};
