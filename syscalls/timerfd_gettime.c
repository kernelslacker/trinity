/*
 * SYSCALL_DEFINE2(timerfd_gettime, int, ufd, struct itimerspec __user *, otmr)
 */
#include <string.h>
#include <sys/timerfd.h>
#include "deferred-free.h"
#include "sanitise.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one timerfd_gettime input arg read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.
 */
#define TIMERFD_GETTIME_POST_STATE_MAGIC	0x54464754UL	/* "TFGT" */
struct timerfd_gettime_post_state {
	unsigned long magic;
	unsigned long otmr;
};

static void sanitise_timerfd_gettime(struct syscallrecord *rec)
{
	struct timerfd_gettime_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, sizeof(struct itimerspec));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a2 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * otmr user-buffer pointer, so the source memcpy would touch a
	 * foreign allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->magic = TIMERFD_GETTIME_POST_STATE_MAGIC;
	snap->otmr  = rec->a2;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: timerfd_gettime(2) returns 0 on success and -1 on failure.
 * On success the kernel writes a struct itimerspec to *otmr whose two
 * timespec fields (it_value, it_interval) carry the time remaining until
 * the next expiration and the configured reload interval.  POSIX requires
 * the tv_nsec component of every timespec to be in [0, 999_999_999]; the
 * kernel's hrtimer_get_remaining() path is responsible for normalising
 * the value before copy-out.  A tv_nsec >= 1e9 in the returned struct is
 * a smoking-gun normalisation bug and must never reach userspace.
 *
 * Snapshot pattern matches ce5cb5f6cbc9 (statmount) and e7a5218fee4b
 * (prlimit64): the user out-pointer is captured at sanitise time into a
 * heap struct in rec->post_state so a sibling scribbling rec->a2 between
 * syscall return and post entry cannot redirect the source memcpy at a
 * foreign allocation.  Two-level looks_like_corrupted_ptr guard: outer
 * check on the snapshot pointer itself, inner check on the snapshot's
 * inner otmr field (defense in depth against wholesale stomps).
 *
 * Binary check: no sampling.  Reading two longs out of a user buffer and
 * comparing each against 1e9 is cheap enough to run on every successful
 * call.
 */
static void post_timerfd_gettime(struct syscallrecord *rec)
{
	struct timerfd_gettime_post_state *snap =
		(struct timerfd_gettime_post_state *) rec->post_state;
	struct itimerspec first;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_timerfd_gettime: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * timerfd_gettime_post_state.  A cookie mismatch means snap does
	 * not point at our struct -- abandon rather than feed wild bytes
	 * into the inner-field deref.
	 */
	if (snap->magic != TIMERFD_GETTIME_POST_STATE_MAGIC) {
		outputerr("post_timerfd_gettime: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->otmr == 0)
		goto out_free;

	{
		void *otmr = (void *)(unsigned long) snap->otmr;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner otmr
		 * field.  Reject pid-scribbled otmr before deref.
		 */
		if (looks_like_corrupted_ptr(rec, otmr)) {
			outputerr("post_timerfd_gettime: rejected suspicious otmr=%p (post_state-scribbled?)\n",
				  otmr);
			goto out_free;
		}
	}

	memcpy(&first, (struct itimerspec *)(unsigned long) snap->otmr,
	       sizeof(first));

	if (first.it_value.tv_nsec < 0 ||
	    first.it_value.tv_nsec > 999999999L ||
	    first.it_interval.tv_nsec < 0 ||
	    first.it_interval.tv_nsec > 999999999L) {
		output(0,
		       "[oracle:timerfd_gettime] tv_nsec out of range: it_value.tv_nsec=%ld it_interval.tv_nsec=%ld (must be in [0, 999999999])\n",
		       (long) first.it_value.tv_nsec,
		       (long) first.it_interval.tv_nsec);
		{
			struct childdata *c = this_child();

			if (c != NULL && c->stats_ring != NULL)
				stats_ring_enqueue(c->stats_ring,
						   STATS_FIELD_POST_HANDLER_CORRUPT_PTR,
						   0, 1);
			else
				parent_stats.post_handler_corrupt_ptr++;
		}
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_timerfd_gettime = {
	.name = "timerfd_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_FD_TIMERFD, [1] = ARG_STRUCT_PTR_OUT },
	.argname = { [0] = "ufd", [1] = "otmr" },
	.sanitise = sanitise_timerfd_gettime,
	.post = post_timerfd_gettime,
	.flags = NEED_ALARM,
	.rettype = RET_ZERO_SUCCESS,
};
