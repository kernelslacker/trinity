/*
 * SYSCALL_DEFINE2(timerfd_gettime, int, ufd, struct itimerspec __user *, otmr)
 */
#include <sys/timerfd.h>
#include "output-poison.h"
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
 * buffer.  The poison_seed slot travels alongside so the untouched-buffer
 * check in the post handler is pinned against the exact byte pattern
 * stamped at sanitise time -- a stomp of rec->aN cannot redirect the
 * check against an unrelated heap page that happens to still carry the
 * original (or any) byte pattern.
 */
#define TIMERFD_GETTIME_POST_STATE_MAGIC	0x54464754UL	/* "TFGT" */
struct timerfd_gettime_post_state {
	unsigned long magic;
	unsigned long otmr;
	uint64_t poison_seed;
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
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = TIMERFD_GETTIME_POST_STATE_MAGIC;
	snap->otmr  = rec->a2;
	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler asks check_output_struct()
	 * whether the pattern survived intact; if it did on a success
	 * return, the kernel wrote zero bytes despite reporting success.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see (the relocation may have swapped
	 * rec->a2 for a fresh page).
	 */
	snap->poison_seed = poison_output_struct((void *)(unsigned long) rec->a2,
						 sizeof(struct itimerspec), 0);
	post_state_install(rec, snap);
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
 * foreign allocation.  The snap is registered in the ownership table at
 * install time and the post handler gates entry through
 * post_state_claim_owned(), which runs the canonical shape -> ownership
 * -> magic check before any inner-field deref -- a stale same-type
 * snapshot still readable in the deferred-free queue, or a sibling
 * scribble of rec->post_state with a heap-shaped pointer at a foreign
 * allocation, is rejected before the otmr field is touched.
 *
 * Binary check: no sampling.  Reading two longs out of a user buffer and
 * comparing each against 1e9 is cheap enough to run on every successful
 * call.
 */
static void post_timerfd_gettime(struct syscallrecord *rec)
{
	struct timerfd_gettime_post_state *snap =
		post_state_claim_owned(rec, TIMERFD_GETTIME_POST_STATE_MAGIC,
				       __func__);
	struct itimerspec first;

	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->otmr == 0)
		goto out_free;

	/*
	 * Untouched-buffer check: timerfd_gettime returned 0 (success) but
	 * the user buffer still byte-for-byte matches the poison pattern we
	 * stamped at sanitise time -- the kernel never called copy_to_user()
	 * at all.  Bumps the shared post_handler_untouched_out_buf counter;
	 * the tv_nsec range oracle below will still fire (poison bytes do
	 * not happen to look like a valid tv_nsec) but the dedicated counter
	 * is the cheaper, no-re-issue signal that dedups against the other
	 * ARG_STRUCT_PTR_OUT consumers.
	 */
	if (check_output_struct((const void *)(unsigned long) snap->otmr,
				sizeof(struct itimerspec),
				snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!post_snapshot_or_skip(&first,
				   (const void *)(unsigned long) snap->otmr,
				   sizeof(first)))
		goto out_free;

	if (first.it_value.tv_nsec < 0 ||
	    first.it_value.tv_nsec > 999999999L ||
	    first.it_interval.tv_nsec < 0 ||
	    first.it_interval.tv_nsec > 999999999L) {
		output(0,
		       "[oracle:timerfd_gettime] tv_nsec out of range: it_value.tv_nsec=%ld it_interval.tv_nsec=%ld (must be in [0, 999999999])\n",
		       (long) first.it_value.tv_nsec,
		       (long) first.it_interval.tv_nsec);
		post_handler_corrupt_ptr_bump_at(rec, NULL,
						 CORRUPT_PTR_SITE_TIMERFD_GETTIME);
	}

out_free:
	post_state_release(rec, snap);
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
