/*
 * SYSCALL_DEFINE6(io_pgetevents,
 *                 aio_context_t, ctx_id,
 *                 long, min_nr,
 *                 long, nr,
 *                 struct io_event __user *, events,
 *                 struct __kernel_timespec __user *, timeout,
 *                 const struct __aio_sigset __user *, usig)
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
#include "utils.h"

/*
 * Snapshot of the io_pgetevents events OUT-buffer pointer, its byte
 * size, and the per-call poison seed, captured at sanitise time and
 * consumed by the post handler.  Lives in rec->post_state so a sibling
 * syscall scribbling rec->a4 between the syscall returning and the
 * post handler running cannot redirect the untouched-buffer check at
 * an unrelated user page whose residual bytes happen to still match
 * some earlier call's seed.  A poison_seed of 0 is the
 * sanitise-refused-to-stamp signal (a4 == 0, buf_bytes == 0, or the
 * writable draw was no longer provably readable) and the post handler
 * must no-op the untouched-buffer arm.
 */
#define IO_PGETEVENTS_POST_STATE_MAGIC	0x49504745UL	/* "IPGE" */
#define IO_PGETEVENTS_POISON_SEED	0x49504745504F5321ULL /* "IPGEPOS!" */
struct io_pgetevents_post_state {
	unsigned long magic;
	unsigned long events;
	size_t buf_bytes;
	uint64_t poison_seed;
};

static void sanitise_io_pgetevents(struct syscallrecord *rec)
{
	struct io_pgetevents_post_state *snap;
	struct io_event *events;
	unsigned long ctx;
	size_t buf_bytes;
	void *buf;
	long nr;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * Precondition: ctx_id (a1) must be a live aio_context_t the kernel
	 * has on hand or io_pgetevents short-circuits with -EINVAL inside
	 * lookup_ioctx() before the per-ring event-queue drain runs.
	 * gen_arg_aio_ctx returns 0 (or 1/8 of the time a raw rand64) until
	 * a real io_setup has published into OBJ_AIO_CTX; seed one inline so
	 * io_pgetevents reaches the productive kernel path even on the very
	 * first call in the child.
	 */
	ctx = seed_aio_ctx_if_empty();
	if (ctx != 0)
		rec->a1 = ctx;

	nr = 1 + (rnd_modulo_u32(16));
	events = (struct io_event *) get_writable_address(nr * sizeof(*events));
	if (events == NULL)
		return;
	memset(events, 0, nr * sizeof(*events));

	/*
	 * min_nr biased toward 0 (60%) so io_pgetevents exercises the
	 * non-blocking reap path (drain whatever has already completed and
	 * return immediately) instead of always landing in
	 * read_events()->wait_event_hrtimeout(), which blocks until either
	 * min_nr events complete or NEED_ALARM's SIGALRM tears the call
	 * down.  The blocking arm still gets the remaining 40% so the
	 * wait / timeout / signal-mask interaction path stays covered.
	 */
	rec->a2 = (rnd_modulo_u32(100) < 60) ? 0 : 1;
	rec->a3 = nr;
	rec->a4 = (unsigned long) events;
	rec->a6 = 0;		/* usig=NULL -- no signal mask */

	avoid_shared_buffer_out(&rec->a4, rec->a3 * sizeof(struct io_event));

	/*
	 * a5 (timeout) is typed ARG_TIMESPEC; the generator publishes
	 * a writable pool buffer (or NULL ~10%) for us.  NEED_ALARM caps
	 * any blocking arm a large tv_sec bucket would otherwise produce.
	 */

	/*
	 * Untouched-buffer oracle setup.  Stamp a fixed-pattern poison
	 * over the events buffer AFTER the memset above and AFTER
	 * avoid_shared_buffer_out() has picked the final buffer so the
	 * poison lands on the page the kernel will actually see.  Use a
	 * FIXED seed (not RNG) so --dry-run stays byte-identical.  On
	 * success io_pgetevents returns retval > 0 and the kernel writes
	 * exactly retval * sizeof(struct io_event) bytes via
	 * aio_read_events_ring()'s copy_to_user; a byte-identical match
	 * across those bytes after retval > 0 means copy_to_user was
	 * skipped entirely.  The buffer maxes at 16 * sizeof(io_event) =
	 * 512 bytes, exactly CHECK_OUTPUT_STRUCT_SNAP_MAX, so the post-
	 * side check is never truncated.
	 */
	buf = (void *)(unsigned long) rec->a4;
	buf_bytes = (size_t) rec->a3 * sizeof(struct io_event);

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic     = IO_PGETEVENTS_POST_STATE_MAGIC;
	snap->events    = rec->a4;
	snap->buf_bytes = buf_bytes;
	if (rec->a4 != 0 && buf_bytes > 0 &&
	    range_readable_user(buf, buf_bytes))
		snap->poison_seed = poison_output_struct(buf, buf_bytes,
							 IO_PGETEVENTS_POISON_SEED);

	post_state_install(rec, snap);
}

/*
 * Oracle: io_pgetevents(ctx, min_nr, nr, events, timeout, usig) returns
 * the number of completed events copied to *events on success (>=0) or
 * a negative errno on failure.  On retval > 0 the kernel wrote exactly
 * retval * sizeof(struct io_event) bytes into events; a byte-identical
 * poison pattern across those bytes means aio_read_events_ring()
 * claimed a completion count without running copy_to_user.  retval ==
 * 0 (timeout / non-blocking reap with nothing pending) and every
 * negative return are silent -- no writeback contract, no false
 * positives.  Real dry-run traffic essentially never hits retval > 0
 * (no io_submit issued in --dry-run), which is the intent: the oracle
 * fires when it fires.
 *
 * Measure-only: no re-issue, no argument mutation, no oracle output
 * beyond the counter bump.
 */
static void post_io_pgetevents(struct syscallrecord *rec)
{
	struct io_pgetevents_post_state *snap;
	size_t check_bytes;
	long retval;

	snap = post_state_claim_owned(rec, IO_PGETEVENTS_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	retval = (long) rec->retval;
	if (retval <= 0)
		goto out_release;
	if (snap->poison_seed == 0)
		goto out_release;

	/*
	 * Bound the check by the buffer we actually poisoned so a broken
	 * kernel returning retval > nr can't drive us to read past the
	 * allocation.  retval * sizeof <= buf_bytes in every good return.
	 */
	check_bytes = (size_t) retval * sizeof(struct io_event);
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

struct syscallentry syscall_io_pgetevents = {
	.name = "io_pgetevents",
	.num_args = 6,
	.argtype = { [0] = ARG_AIO_CTX, [1] = ARG_LEN, [2] = ARG_LEN, [3] = ARG_ADDRESS, [4] = ARG_TIMESPEC, [5] = ARG_ADDRESS },
	.argname = { [0] = "ctx_id", [1] = "min_nr", [2] = "nr", [3] = "events", [4] = "timeout", [5] = "usig" },
	.group = GROUP_VFS,
	.flags = NEED_ALARM,
	.sanitise = sanitise_io_pgetevents,
	.post = post_io_pgetevents,
	.bound_arg = 3,
};
