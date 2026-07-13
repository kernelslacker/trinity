/*
 * SYSCALL_DEFINE3(setitimer, int, which, struct itimerval __user *, value, struct itimerval __user *, ovalue)
 */
#include <sys/time.h>
#include "output-poison.h"
#include "sanitise.h"
#include "shm.h"
#include "stats_ring.h"
#include "trinity.h"
#include "utils.h"

static unsigned long setitimer_which[] = {
	ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF,
};

/*
 * Snapshot of the ovalue OUT-pointer arg captured at sanitise time and
 * consumed by the post handler.  Lives in rec->post_state so a sibling
 * syscall scribbling rec->a3 between the syscall returning and the post
 * handler running cannot redirect the check at a foreign user buffer.
 */
#define SETITIMER_POST_STATE_MAGIC	0x5349544DUL	/* "SITM" */
struct setitimer_post_state {
	unsigned long magic;
	unsigned long ovalue;
	/*
	 * Seed for the poison pattern stamped into the ovalue OUT buffer
	 * at sanitise time.  Returned by poison_output_struct() and fed
	 * back into check_output_struct() in the post handler so a stomp
	 * of rec->aN cannot redirect the check against an unrelated heap
	 * page that happens to still carry the original (or any) byte
	 * pattern.
	 */
	uint64_t poison_seed;
};

static void sanitise_setitimer(struct syscallrecord *rec)
{
	struct setitimer_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a3, sizeof(struct itimerval));

	/*
	 * Snapshot the ovalue arg for the post oracle.  Without this the
	 * post handler reads rec->a3 at post-time, when a sibling syscall
	 * may have scribbled the slot: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original value
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_setitimer() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SETITIMER_POST_STATE_MAGIC;
	snap->ovalue = rec->a3;
	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler asks check_output_struct()
	 * whether the pattern survived intact; if it did on a success
	 * return the kernel wrote zero bytes despite reporting success.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see (the relocation may have
	 * swapped rec->a3 for a fresh page).
	 *
	 * ovalue is ARG_ADDRESS (optional) -- rec->a3 == 0 is a legitimate
	 * "caller does not want the previous value" call and the kernel
	 * will simply not touch the buffer.  Skip the stamp in that case;
	 * writing through NULL would SIGSEGV inside poison_output_struct
	 * and the post handler's matching rec->a3 == 0 gate suppresses
	 * the check for a NULL ovalue.
	 */
	if (rec->a3 != 0)
		snap->poison_seed = poison_output_struct((void *)(unsigned long) rec->a3,
							 sizeof(struct itimerval), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: setitimer(2) returns 0 on success.  When the caller passes a
 * non-NULL ovalue the kernel is required to copy the previous itimerval
 * out through it.  Sanitise stamps a per-call poison pattern into that
 * buffer before the syscall runs; on a success return the post handler
 * asks check_output_struct() whether the pattern survived intact.  If it
 * did, the kernel wrote zero bytes despite reporting success -- a torn
 * copy_to_user, a "return 0 before fill" early-exit, or a mis-wired
 * compat wrapper.  O(sizeof(struct itimerval)) memcmp, no re-issue;
 * bumps the shared post_handler_untouched_out_buf counter.
 *
 * The interval echoed back is caller-supplied, so no value-range oracle
 * lives here -- the untouched-buffer check is the only signal.
 */
static void post_setitimer(struct syscallrecord *rec)
{
	struct setitimer_post_state *snap;

	snap = post_state_claim_owned(rec, SETITIMER_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	/*
	 * ovalue is ARG_ADDRESS: a NULL a3 is a legitimate call that
	 * asks the kernel to skip the previous-value copy-out entirely.
	 * No buffer means nothing to check -- returning here avoids a
	 * spurious untouched-out-buf bump on the well-formed NULL case.
	 */
	if (snap->ovalue == 0)
		goto out_free;

	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->ovalue,
					     sizeof(struct itimerval),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_setitimer = {
	.flags = AVOID_SYSCALL,		/* setitimer interferes with alarm() */
	.name = "setitimer",
	.group = GROUP_TIME,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_ITIMERVAL, [2] = ARG_ADDRESS },
	.argname = { [0] = "which", [1] = "value", [2] = "ovalue" },
	.arg_params[0].list = ARGLIST(setitimer_which),
	.sanitise = sanitise_setitimer,
	.post = post_setitimer,
	.rettype = RET_ZERO_SUCCESS,
};
