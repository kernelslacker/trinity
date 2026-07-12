/*
 * SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
	 struct io_event __user *, result)
 */
#include <linux/aio_abi.h>
#include <stdint.h>
#include <string.h>
#include "objects.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "fd.h"

/*
 * Snapshot of the io_cancel result pointer plus the poison seed read
 * by the post oracle, captured at sanitise time and consumed by the
 * post handler.  Lives in rec->post_state, a slot the syscall ABI does
 * not expose, so a sibling syscall scribbling rec->a3 between the
 * syscall returning and the post handler running cannot redirect the
 * poison check against an unrelated heap page whose residual bytes
 * happen to still match some earlier call's seed.  A poison_seed of 0
 * means the sanitise-time writability check refused to stamp poison
 * for this call (result is ARG_ADDRESS so a3 == 0 is a documented
 * "don't write back", or the writable draw was no longer provably
 * mapped) and the post handler must no-op the untouched-buffer arm.
 */
#define IO_CANCEL_POST_STATE_MAGIC	0x494F434EUL	/* "IOCN" */
struct io_cancel_post_state {
	unsigned long magic;
	unsigned long result;
	uint64_t poison_seed;
};

static void sanitise_io_cancel(struct syscallrecord *rec)
{
	struct io_cancel_post_state *snap;
	struct iocb *iocb;
	struct io_event *result;
	struct object *pool_obj = NULL;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	iocb = (struct iocb *) get_writable_address(sizeof(*iocb));
	if (iocb == NULL)
		return;
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_lio_opcode = IOCB_CMD_PREAD;
	iocb->aio_fildes = get_random_fd();
	iocb->aio_buf = (__u64)(unsigned long) get_writable_address(4096);
	iocb->aio_nbytes = 4096;

	/*
	 * 60% of the time, pick a real outstanding (ctx, aio_data) from
	 * the OBJ_AIO_IOCB pool published by post_io_submit so the kernel
	 * actually finds the request and runs its ->cancel handler.  The
	 * remaining 40% keep the original random-iocb path so the
	 * not-found / EINVAL branch in __io_submit_cancel keeps coverage.
	 *
	 * Empty pool falls through to 100% random, which is what shipped
	 * before the pool was introduced.
	 */
	if (rnd_modulo_u32(100) < 60 &&
	    objects_pool_empty(OBJ_LOCAL, OBJ_AIO_IOCB) == false) {
		pool_obj = get_random_object(OBJ_AIO_IOCB, OBJ_LOCAL);
		if (objpool_check(pool_obj, OBJ_AIO_IOCB)) {
			rec->a1 = pool_obj->aio_iocb_obj.ctx;
			iocb->aio_data = pool_obj->aio_iocb_obj.aio_data;
		}
	}

	result = (struct io_event *) get_writable_address(sizeof(*result));
	if (result == NULL)
		return;
	memset(result, 0, sizeof(*result));

	rec->a2 = (unsigned long) iocb;
	avoid_shared_buffer_inout(&rec->a2, sizeof(struct iocb));
	rec->a3 = (unsigned long) result;

	avoid_shared_buffer_out(&rec->a3, sizeof(struct io_event));

	/*
	 * Snapshot the result user pointer plus a per-call poison pattern
	 * into the user io_event the kernel is about to fill.  The post
	 * handler feeds the seed back into
	 * check_output_struct_user_or_skip(); a byte-identical poison
	 * after retval == 0 means the kernel skipped copy_to_user()
	 * entirely -- io_cancel with a non-NULL result contracts to
	 * write the cancelled iocb's io_event there on success.  Gate on
	 * range_readable_user() which folds both the NULL gate (result
	 * is ARG_ADDRESS so a3 == 0 is a documented "don't write back")
	 * and the unmapped-address gate into one call: NULL and unproven
	 * ranges both return false, so poison_seed stays 0
	 * (zmalloc_tracked cleared it) and the post handler no-ops the
	 * untouched-buffer arm.  Done after avoid_shared_buffer_out() so
	 * the poison lands on the final buffer the kernel will see (the
	 * relocation may have swapped rec->a3 for a fresh page).
	 *
	 * Hit rate here is inherently low: success requires a valid aio
	 * context AND an in-flight cancellable iocb, so the common
	 * EINVAL / EAGAIN paths (and every dry-run) leave the oracle
	 * silent.  That is the point -- silent on error is what keeps
	 * this false-positive-free.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic  = IO_CANCEL_POST_STATE_MAGIC;
	snap->result = rec->a3;

	buf = (void *)(unsigned long) rec->a3;
	if (range_readable_user(buf, sizeof(struct io_event)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct io_event),
							 0);

	post_state_install(rec, snap);
}

/*
 * Oracle: io_cancel(ctx_id, iocb, result) returns 0 on success and -1
 * on failure (commonly EINVAL for a not-found iocb, EAGAIN when the
 * request could not be cancelled, or EFAULT).  On success, if result
 * != NULL the kernel writes the cancelled request's io_event to
 * *result.  A byte-identical poison pattern after success on a
 * non-NULL result means the copy_to_user() path skipped the writeback
 * entirely; bump the shared post_handler_untouched_out_buf counter.
 * The NULL-arg path and every error return are silent -- no writeback
 * contract, no false positives.
 *
 * Measure-only: no re-issue, no argument mutation, no oracle output
 * beyond the counter bump.
 */
static void post_io_cancel(struct syscallrecord *rec)
{
	struct io_cancel_post_state *snap;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, IO_CANCEL_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	/*
	 * Untouched-buffer check: io_cancel returned 0 with a non-NULL
	 * result, but the io_event still byte-for-byte matches the
	 * poison pattern we stamped at sanitise time -- the kernel never
	 * called copy_to_user() at all.  Cheap: sizeof(struct io_event)
	 * memcmp, no re-issue, so runs on every success rather than
	 * under ONE_IN().  A poison_seed of 0 is the
	 * sanitise-refused-to-stamp signal (NULL result or unmapped
	 * writable draw) -- gating on it here also doubles as the
	 * NULL-arg short-circuit, so no separate snap->result == 0
	 * check is needed.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->result,
					     sizeof(struct io_event),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_io_cancel = {
	.name = "io_cancel",
	.num_args = 3,
	.argtype = { [0] = ARG_AIO_CTX, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "ctx_id", [1] = "iocb", [2] = "result" },
	.group = GROUP_VFS,
	.sanitise = sanitise_io_cancel,
	.post = post_io_cancel,
};
