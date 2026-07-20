/*
 * SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events, int, maxevents, int, timeout)
 *
 * When  successful, returns the number of file descriptors ready for the requested I/O,
 * or zero if no file descriptor became ready during the requested timeout milliseconds.
 * When an error occurs, returns -1 and errno is set appropriately.
 */
#include <limits.h>
#include <stdint.h>
#include <sys/epoll.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "stats.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the events OUT-buffer pointer, its byte size, and the
 * per-call poison seed, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state so a sibling syscall scribbling
 * rec->a2 between the syscall returning and the post handler running
 * cannot redirect the untouched-buffer check at an unrelated user page
 * whose residual bytes happen to still match some earlier call's seed.
 * A poison_seed of 0 is the sanitise-refused-to-stamp signal (a2 == 0,
 * maxevents <= 0, or the writable draw was no longer provably readable)
 * and the post handler must no-op the untouched-buffer arm.
 */
#define EPOLL_WAIT_POST_STATE_MAGIC	0x45505741UL	/* "EPWA" */
#define EPOLL_WAIT_POISON_SEED		0x45504F4C57414921ULL /* "EPOLWAI!" */
struct epoll_wait_post_state {
	unsigned long magic;
	unsigned long events;
	size_t buf_bytes;
	uint64_t poison_seed;
};

/*
 * Bias maxevents toward sizes the kernel actually exercises rather than
 * the [1,128] range default.  Bucket 8 reflects the libc default many
 * userspace event loops use; 64/1024 push ep_send_events down the
 * larger-batch copy_to_user path; 0 / negative keeps the early
 * EINVAL reject warm.
 */
static int pick_maxevents(void)
{
	switch (rnd_modulo_u32(10)) {
	case 0:		return 1;
	case 1:
	case 2:
	case 3:		return 8;
	case 4:
	case 5:		return 64;
	case 6:
	case 7:		return 1024;
	case 8:		return 0;
	default:	return -1;
	}
}

/*
 * Timeout buckets.  Short positive values dominate so the child can't
 * stall.  INT_MAX and the negative-but-not-(-1) bucket keep the
 * input-validation path covered.
 */
static unsigned long pick_timeout_ms(void)
{
	switch (rnd_modulo_u32(10)) {
	case 0:		return (unsigned long) -1;		/* block forever */
	case 1:
	case 2:		return 0;				/* immediate */
	case 3:
	case 4:
	case 5:
	case 6:		return 1 + rnd_modulo_u32(100);		/* short wait */
	case 7:		return INT_MAX;				/* huge */
	case 8:		return (unsigned long)(unsigned int) -2;/* negative non-(-1) */
	default:	return rnd_u32();
	}
}

/*
 * Attribute why (a3 > 0 && a2 == 0) still holds at sanitise exit --
 * the state the arg-coupling validator will reject as EFAULT-shaped
 * without dispatching the syscall.  Companion to the identical helper
 * in epoll_pwait.c; kept per-file to match the file-local static
 * pattern (pick_maxevents / pick_timeout_ms) instead of hoisting to a
 * shared header just for two callers.  See stats.h for the bucket
 * definitions.
 */
static void record_null_events_cause(unsigned long initial_a2,
				     struct syscallrecord *rec)
{
	if ((long) rec->a3 <= 0 || rec->a2 != 0)
		return;
	if (initial_a2 == 0)
		__atomic_add_fetch(&shm->stats.epoll_volatility.wait_null_events_alloc_fail,
				   1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(&shm->stats.epoll_volatility.wait_null_events_shared_reject,
				   1, __ATOMIC_RELAXED);
}

static void sanitise_epoll_wait(struct syscallrecord *rec)
{
	struct epoll_wait_post_state *snap;
	unsigned long initial_a2 = rec->a2;
	long mx;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	rec->a3 = (unsigned long) pick_maxevents();
	rec->a4 = pick_timeout_ms();

	/*
	 * Buffer sizing for the events output uses a sane minimum so a
	 * negative or zero maxevents picked above doesn't underflow the
	 * allocation hint -- the kernel still sees the chosen rec->a3.
	 */
	mx = (long) rec->a3;
	{
		unsigned long bytes = (mx > 0 ? mx : 1) * sizeof(struct epoll_event);

		avoid_shared_buffer_out(&rec->a2, bytes);
	}

	record_null_events_cause(initial_a2, rec);

	/*
	 * Untouched-buffer oracle setup.  Stamp a fixed-pattern poison
	 * over the full maxevents-sized events buffer AFTER
	 * avoid_shared_buffer_out() has picked the final buffer so the
	 * poison lands on the page the kernel will actually see.  Use a
	 * FIXED seed (not RNG) so --dry-run stays byte-identical to a
	 * build without this oracle.  On success epoll_wait returns
	 * retval >= 0 and the kernel writes exactly
	 * retval * sizeof(struct epoll_event) bytes via ep_send_events()'s
	 * copy_to_user; a byte-identical match across those bytes after
	 * retval > 0 means copy_to_user was skipped entirely.  Gated on
	 * range_readable_user() so a writable-pool draw that
	 * avoid_shared_buffer_out moved to an address no longer provably
	 * mapped does not SIGSEGV the sanitiser inside
	 * poison_output_struct's byte-walk.  Non-positive maxevents skips
	 * the stamp -- the kernel rejects those with -EINVAL before
	 * touching the buffer.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic       = EPOLL_WAIT_POST_STATE_MAGIC;
	snap->events      = rec->a2;
	snap->buf_bytes   = 0;
	snap->poison_seed = 0;

	if (mx > 0 && rec->a2 != 0) {
		size_t poison_bytes = (size_t) mx * sizeof(struct epoll_event);
		void *buf = (void *)(unsigned long) rec->a2;

		if (range_readable_user(buf, poison_bytes)) {
			snap->buf_bytes   = poison_bytes;
			snap->poison_seed = poison_output_struct(buf, poison_bytes,
								 EPOLL_WAIT_POISON_SEED);
		}
	}

	post_state_install(rec, snap);
}

/*
 * Kernel ABI: epoll_wait(2) on success returns the count of ready file
 * descriptors copied into the user events array — a value in [0, maxevents]
 * computed by ep_send_events() walking fs/eventpoll.c's ready list. Failure
 * returns -1UL with EBADF/EFAULT/EINTR/EINVAL via the syscall return path.
 * Anything > maxevents (excluding -1UL) is a structural ABI regression: a
 * sign-extension tear in the syscall return path, a torn write of the count
 * by a parallel signal-restart path, or -errno leaking through the success
 * return slot instead of the errno slot.
 *
 * Second oracle: untouched-buffer.  On retval > 0 the kernel wrote exactly
 * retval * sizeof(struct epoll_event) bytes; a byte-identical poison
 * pattern across those bytes means ep_send_events() claimed a completion
 * count without running copy_to_user.  retval == 0 (timeout / nothing
 * ready, nothing was written and nothing to check) and every negative
 * return are silent -- no writeback contract, no false positives.  The
 * check_output_struct_user_or_skip SNAP_MAX cap silently drops checks
 * larger than that ceiling, so multi-KB (maxevents up to 1024) requests
 * trade coverage for a bounded post-handler cost -- we cap check_bytes at
 * snap->buf_bytes and let the helper's own cap take it from there.
 * Measure-only: no re-issue, no argument mutation, no oracle output
 * beyond the counter bump.
 */
static void post_epoll_wait(struct syscallrecord *rec)
{
	struct epoll_wait_post_state *snap;
	long retval    = (long) rec->retval;
	long maxevents = (long) get_arg_snapshot(rec, 3);
	size_t check_bytes;

	snap = post_state_claim_owned(rec, EPOLL_WAIT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if (retval == -1L)
		goto out_release;
	if (maxevents <= 0)
		goto out_release;
	if (retval > maxevents) {
		outputerr("post_epoll_wait: rejecting retval %ld > maxevents %ld\n",
			  retval, maxevents);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_release;
	}

	if (retval <= 0)
		goto out_release;
	if (snap->poison_seed == 0)
		goto out_release;

	/*
	 * Bound the check by the buffer we actually poisoned so a broken
	 * kernel returning retval > maxevents (already rejected above)
	 * cannot drive us to read past the allocation.
	 */
	check_bytes = (size_t) retval * sizeof(struct epoll_event);
	if (check_bytes > snap->buf_bytes)
		check_bytes = snap->buf_bytes;

	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->events,
					     check_bytes,
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_epoll_wait = {
	.name = "epoll_wait",
	.num_args = 4,
	.argtype = { [0] = ARG_FD_EPOLL, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "epfd", [1] = "events", [2] = "maxevents", [3] = "timeout" },
	.sanitise = sanitise_epoll_wait,
	.post = post_epoll_wait,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	/* a3 (maxevents) is read in post to bound retval -- snapshot it so
	 * a sibling stomp between BEFORE and AFTER cannot fabricate a
	 * post_handler_corrupt_ptr by overwriting the bound. */
	.arg_snapshot_mask = (1u << 2),
};
