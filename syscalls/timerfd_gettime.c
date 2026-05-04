/*
 * SYSCALL_DEFINE2(timerfd_gettime, int, ufd, struct itimerspec __user *, otmr)
 */
#include <string.h>
#include <sys/timerfd.h>
#include "deferred-free.h"
#include "sanitise.h"
#include "shm.h"
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
struct timerfd_gettime_post_state {
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

	avoid_shared_buffer(&rec->a2, sizeof(struct itimerspec));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a2 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * otmr user-buffer pointer, so the source memcpy would touch a
	 * foreign allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->otmr = rec->a2;
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
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_timerfd_gettime = {
	.name = "timerfd_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_FD_TIMERFD, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "ufd", [1] = "otmr" },
	.sanitise = sanitise_timerfd_gettime,
	.post = post_timerfd_gettime,
	.flags = NEED_ALARM,
	.rettype = RET_ZERO_SUCCESS,
};
