/*
 * SYSCALL_DEFINE2(timer_gettime, timer_t, timer_id, struct itimerspec __user *, setting)
 */
#include <time.h>
#include "output-poison.h"
#include "sanitise.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one timer_gettime input arg read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.
 */
#define TIMER_GETTIME_POST_STATE_MAGIC	0x54475454UL	/* "TGTT" */
struct timer_gettime_post_state {
	unsigned long magic;
	unsigned long setting;
	/*
	 * Seed for the poison pattern stamped into the setting buffer at
	 * sanitise time.  Returned by poison_output_struct() and fed back
	 * into check_output_struct() in the post handler so a stomp of
	 * rec->aN cannot redirect the check against an unrelated heap page
	 * that happens to still carry a residual pattern from an earlier
	 * call.
	 */
	uint64_t poison_seed;
};

static void sanitise_timer_gettime(struct syscallrecord *rec)
{
	struct timer_gettime_post_state *snap;
	void *buf;
	int32_t tid;

	/*
	 * Precondition: timer_id (a1) must reference a kernel-allocated
	 * k_itimer or timer_gettime short-circuits with -EINVAL inside
	 * posix_timer_get_by_id() before the hrtimer remaining-time path
	 * runs.  gen_arg_timerid returns a value from OBJ_TIMERID when the
	 * pool has entries, otherwise a random small int from
	 * get_random_timerid()'s pool-empty fallback that almost never
	 * matches a live id.  Seed one inline so timer_gettime reaches the
	 * productive kernel read path (hrtimer_get_remaining / per-clock
	 * sample) on the very first call in the child.  This is a
	 * non-destructive peek of the timer state, so sharing the pool with
	 * other timer_t consumers is safe -- no destructor double-free risk
	 * of the timer_delete shape.
	 */
	tid = seed_timerid_if_empty();
	if (tid >= 0)
		rec->a1 = (unsigned long) tid;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, sizeof(struct itimerspec));

	/*
	 * ARG_NON_NULL_ADDRESS draws from get_writable_address(), which
	 * returns NULL when the writable pool cannot back the requested
	 * mapping_sizes[] pick.  Skip the poison + snap install on those
	 * calls -- writing a poison pattern to a NULL or otherwise not-
	 * provably-writable user pointer would SIGSEGV inside the
	 * sanitiser and mask the syscall path we are trying to fuzz.  On
	 * skip, rec->post_state stays 0 -- post_state_claim_owned()
	 * returns NULL and the post handler no-ops without ever touching
	 * the pointer.
	 */
	buf = (void *)(unsigned long) rec->a2;
	if (!range_readable_user(buf, sizeof(struct itimerspec)))
		return;

	/*
	 * Snapshot the one input arg + the output-buffer poison seed for
	 * the post oracle.  Without the a2 snap the post handler reads
	 * rec->a2 at post-time, when a sibling syscall may have scribbled
	 * the slot: looks_like_corrupted_ptr() cannot tell a real-but-
	 * wrong heap address from the original setting user-buffer
	 * pointer, so the source memcpy would touch a foreign allocation.
	 * post_state is private to the post handler.  Stamp the poison
	 * after avoid_shared_buffer_out() so it lands on the final buffer
	 * the kernel will see; the returned seed is fed back into
	 * check_output_struct() in the post handler.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = TIMER_GETTIME_POST_STATE_MAGIC;
	snap->setting     = rec->a2;
	snap->poison_seed = poison_output_struct(buf,
						 sizeof(struct itimerspec), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: timer_gettime(2) returns 0 on success and -1 on failure.  On
 * success the kernel writes a struct itimerspec to *setting whose two
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
 * foreign allocation.  The snap is registered in the ownership table at
 * install time and the post handler gates entry through
 * post_state_claim_owned(), which runs the canonical shape -> ownership
 * -> magic check before any inner-field deref -- a stale same-type
 * snapshot still readable in the deferred-free queue, or a sibling
 * scribble of rec->post_state with a heap-shaped pointer at a foreign
 * allocation, is rejected before the setting field is touched.
 *
 * Binary check: no sampling.  Reading two longs out of a user buffer and
 * comparing each against 1e9 is cheap enough to run on every successful
 * call.
 */
static void post_timer_gettime(struct syscallrecord *rec)
{
	struct timer_gettime_post_state *snap =
		post_state_claim_owned(rec, TIMER_GETTIME_POST_STATE_MAGIC,
				       __func__);
	struct itimerspec first;

	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->setting == 0)
		goto out_free;

	if (!post_snapshot_or_skip(&first,
				   (const void *)(unsigned long) snap->setting,
				   sizeof(first)))
		goto out_free;

	/*
	 * Untouched-buffer check: timer_gettime returned 0 (success) but
	 * the user buffer still byte-for-byte matches the poison pattern
	 * we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all, or short-copied and left an
	 * uninitialised-field tail readable in user memory (a kernel->
	 * user infoleak).  Cheap (byte-walk against a repeating 8-byte
	 * pattern, no re-issue syscall), so runs on every success sample.
	 * Counts against the shared post_handler_untouched_out_buf slot;
	 * the tv_nsec check below still runs -- an intact poison pattern
	 * has bytes well outside [0, 999999999] so it will fire too, but
	 * this counter is the dedicated no-re-issue signal.
	 */
	if (check_output_struct(&first, sizeof(first), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (first.it_value.tv_nsec < 0 ||
	    first.it_value.tv_nsec > 999999999L ||
	    first.it_interval.tv_nsec < 0 ||
	    first.it_interval.tv_nsec > 999999999L) {
		output(0,
		       "[oracle:timer_gettime] tv_nsec out of range: it_value.tv_nsec=%ld it_interval.tv_nsec=%ld (must be in [0, 999999999])\n",
		       (long) first.it_value.tv_nsec,
		       (long) first.it_interval.tv_nsec);
		post_handler_corrupt_ptr_bump_at(rec, NULL,
						 CORRUPT_PTR_SITE_TIMER_GETTIME);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_timer_gettime = {
	.name = "timer_gettime",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_TIMERID, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "timer_id", [1] = "setting" },
	.sanitise = sanitise_timer_gettime,
	.post = post_timer_gettime,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
