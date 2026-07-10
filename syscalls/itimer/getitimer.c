/*
 * SYSCALL_DEFINE2(getitimer, int, which, struct itimerval __user *, value)
 */
#include <sys/time.h>
#include "sanitise.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

static unsigned long getitimer_which[] = {
	ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF,
};

/*
 * Snapshot of the one getitimer input arg read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.
 */
#define GETITIMER_POST_STATE_MAGIC	0x4749544DUL	/* "GITM" */
struct getitimer_post_state {
	unsigned long magic;
	unsigned long value;
};

static void sanitise_getitimer(struct syscallrecord *rec)
{
	struct getitimer_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a2, sizeof(struct itimerval));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a2 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * value user-buffer pointer, so the source memcpy would touch a
	 * foreign allocation.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_getitimer() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETITIMER_POST_STATE_MAGIC;
	snap->value = rec->a2;
	post_state_install(rec, snap);
}

/*
 * Oracle: getitimer(2) returns 0 on success and -1 on failure.  On
 * success the kernel writes a struct itimerval to *value whose two
 * timeval fields (it_value, it_interval) carry the time remaining until
 * the next expiration and the configured reload interval.  POSIX requires
 * the tv_usec component of every timeval to be in [0, 999_999]; the
 * kernel's get_itimer() / cputime_to_timeval() path is responsible for
 * normalising the value before copy-out.  A tv_usec >= 1e6 in the
 * returned struct is a smoking-gun normalisation bug and must never
 * reach userspace.
 *
 * Snapshot pattern matches ce5cb5f6cbc9 (statmount) and e7a5218fee4b
 * (prlimit64): the user out-pointer is captured at sanitise time into a
 * heap struct in rec->post_state.  post_state_install() registers the
 * snapshot in the ownership table in the same step; post_state_claim_owned()
 * then runs the canonical shape -> ownership -> magic gate before any
 * field is dereferenced, so a sibling scribble of rec->post_state pointing
 * at a still-readable same-type snapshot in the deferred-free queue is
 * rejected -- the magic cookie alone would let it pass, since it proves
 * struct-type, not per-attempt ownership.
 *
 * Binary check: no sampling.  Reading two longs out of a user buffer and
 * comparing each against 1e6 is cheap enough to run on every successful
 * call.
 */
static void post_getitimer(struct syscallrecord *rec)
{
	struct getitimer_post_state *snap;
	struct itimerval first;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETITIMER_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->value == 0)
		goto out_free;

	if (!post_snapshot_or_skip(&first,
				   (const void *)(unsigned long) snap->value,
				   sizeof(first)))
		goto out_free;

	if (first.it_value.tv_usec < 0 ||
	    first.it_value.tv_usec > 999999L ||
	    first.it_interval.tv_usec < 0 ||
	    first.it_interval.tv_usec > 999999L) {
		output(0,
		       "[oracle:getitimer] tv_usec out of range: it_value.tv_usec=%ld it_interval.tv_usec=%ld (must be in [0, 999999])\n",
		       (long) first.it_value.tv_usec,
		       (long) first.it_interval.tv_usec);
		post_handler_corrupt_ptr_bump_at(rec, NULL,
						 CORRUPT_PTR_SITE_GETITIMER);
	}

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_getitimer = {
	.name = "getitimer",
	.group = GROUP_TIME,
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "which", [1] = "value" },
	.arg_params[0].list = ARGLIST(getitimer_which),
	.sanitise = sanitise_getitimer,
	.post = post_getitimer,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
