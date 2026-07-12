/*
 * SYSCALL_DEFINE3(mq_getsetattr, mqd_t, mqdes,
	const struct mq_attr __user *, u_mqstat,
	struct mq_attr __user *, u_omqstat)
 */
#include <mqueue.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the mq_getsetattr u_omqstat pointer plus the poison seed
 * read by the post oracle, captured at sanitise time and consumed by
 * the post handler.  Lives in rec->post_state, a slot the syscall ABI
 * does not expose, so a sibling syscall scribbling rec->a3 between the
 * syscall returning and the post handler running cannot redirect the
 * poison check against an unrelated heap page whose residual bytes
 * happen to still match some earlier call's seed.  A poison_seed of 0
 * means the sanitise-time writability check refused to stamp poison
 * for this call (u_omqstat is ARG_ADDRESS so a3 == 0 is a documented
 * "don't write back", or the writable draw was no longer provably
 * mapped) and the post handler must no-op the untouched-buffer arm.
 */
#define MQ_GETSETATTR_POST_STATE_MAGIC	0x4D514753UL	/* "MQGS" */
struct mq_getsetattr_post_state {
	unsigned long magic;
	unsigned long u_omqstat;
	uint64_t poison_seed;
};

static void sanitise_mq_getsetattr(struct syscallrecord *rec)
{
	struct mq_getsetattr_post_state *snap;
	struct mq_attr *mqstat, *omqstat;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	mqstat = (struct mq_attr *) get_writable_address(sizeof(*mqstat));
	if (mqstat == NULL)
		return;
	memset(mqstat, 0, sizeof(*mqstat));

	/* Only mq_flags is settable: O_NONBLOCK or 0. */
	if (RAND_BOOL())
		mqstat->mq_flags = O_NONBLOCK;

	omqstat = (struct mq_attr *) get_writable_address(sizeof(*omqstat));
	if (omqstat == NULL)
		return;

	rec->a2 = (unsigned long) mqstat;
	rec->a3 = (unsigned long) omqstat;

	avoid_shared_buffer_inout(&rec->a2, sizeof(struct mq_attr));
	avoid_shared_buffer_out(&rec->a3, sizeof(struct mq_attr));

	/*
	 * Snapshot the u_omqstat pointer plus a per-call poison pattern
	 * into the user mq_attr the kernel is about to fill.  The post
	 * handler feeds the seed back into
	 * check_output_struct_user_or_skip(); a byte-identical poison
	 * after retval == 0 means the kernel skipped copy_to_user()
	 * entirely -- mq_getsetattr with a non-NULL u_omqstat contracts
	 * to write the previous attrs there on success.  Gate on
	 * range_readable_user() which folds both the NULL gate
	 * (u_omqstat is ARG_ADDRESS so a3 == 0 is a documented "don't
	 * write back") and the unmapped-address gate into one call: NULL
	 * and unproven ranges both return false, so poison_seed stays 0
	 * (zmalloc_tracked cleared it) and the post handler no-ops the
	 * untouched-buffer arm.  Done after avoid_shared_buffer_out() so
	 * the poison lands on the final buffer the kernel will see (the
	 * relocation may have swapped rec->a3 for a fresh page).
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic     = MQ_GETSETATTR_POST_STATE_MAGIC;
	snap->u_omqstat = rec->a3;

	buf = (void *)(unsigned long) rec->a3;
	if (range_readable_user(buf, sizeof(struct mq_attr)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct mq_attr),
							 0);

	post_state_install(rec, snap);
}

/*
 * Oracle: mq_getsetattr(mqdes, u_mqstat, u_omqstat) returns 0 on
 * success and -1 on failure.  On success, if u_omqstat != NULL the
 * kernel writes the previous mq_attr to *u_omqstat.  A byte-identical
 * poison pattern after success on a non-NULL u_omqstat means the
 * copy_to_user() path skipped the writeback entirely; bump the shared
 * post_handler_untouched_out_buf counter.  The NULL-arg path and every
 * error return are silent -- no writeback contract, no false positives.
 *
 * Measure-only: no re-issue, no argument mutation, no oracle output
 * beyond the counter bump.
 */
static void post_mq_getsetattr(struct syscallrecord *rec)
{
	struct mq_getsetattr_post_state *snap;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, MQ_GETSETATTR_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	/*
	 * Untouched-buffer check: mq_getsetattr returned 0 with a
	 * non-NULL u_omqstat, but the mq_attr still byte-for-byte matches
	 * the poison pattern we stamped at sanitise time -- the kernel
	 * never called copy_to_user() at all.  Cheap: sizeof(struct
	 * mq_attr) memcmp, no re-issue, so runs on every success rather
	 * than under ONE_IN().  A poison_seed of 0 is the
	 * sanitise-refused-to-stamp signal (NULL u_omqstat or unmapped
	 * writable draw) -- gating on it here also doubles as the
	 * NULL-arg short-circuit, so no separate snap->u_omqstat == 0
	 * check is needed above.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->u_omqstat,
					     sizeof(struct mq_attr),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_mq_getsetattr = {
	.name = "mq_getsetattr",
	.group = GROUP_IPC,
	.num_args = 3,
	.argtype = { [0] = ARG_FD_MQ, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "mqdes", [1] = "u_mqstat", [2] = "u_omqstat" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_mq_getsetattr,
	.post = post_mq_getsetattr,
};
