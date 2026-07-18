/*
 * SYSCALL_DEFINE1(time, time_t __user *, tloc)
 */
#include <time.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one time input arg plus the poison seed read by the
 * post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot smear the poison seed
 * against a heap page that happens to still carry a residual pattern
 * from an earlier call.  A poison_seed of 0 means the sanitise-time
 * writability check refused to stamp poison for this call (NULL tloc
 * or a writable-pool draw that is no longer provably mapped) and the
 * post handler must no-op the untouched-buffer check.
 */
#define TIME_POST_STATE_MAGIC	0x54494D45UL	/* "TIME" */
struct time_post_state {
	unsigned long magic;
	unsigned long tloc;
	uint64_t poison_seed;
};

static void sanitise_time(struct syscallrecord *rec)
{
	struct time_post_state *snap;

	rec->post_state = 0;

	/*
	 * tloc bucket: NULL ~30% of the time, non-NULL otherwise.  The
	 * NULL path returns the time only via retval and does not touch
	 * userspace; the non-NULL path additionally copies through to
	 * the user buffer.  Both paths share the same timekeeping read
	 * but diverge in copy_to_user handling, so cover both
	 * deliberately rather than relying on the random pool to land
	 * on NULL.
	 */
	if (rnd_modulo_u32(100) < 30)
		rec->a1 = 0;
	else
		avoid_shared_buffer_out(&rec->a1, sizeof(time_t));

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = TIME_POST_STATE_MAGIC;
	snap->tloc  = rec->a1;
	/*
	 * Stamp a per-call poison pattern into the user time_t the
	 * kernel is about to fill.  The post handler feeds the seed
	 * back into check_output_struct(); a byte-identical poison
	 * after a non-error return means the kernel skipped
	 * copy_to_user() entirely -- time(2) with a non-NULL tloc
	 * contracts to write the epoch value there on success.  Gate
	 * on range_readable_user() so a writable-pool draw that
	 * avoid_shared_buffer_out() moved to an address that is no
	 * longer provably mapped -- e.g. a sibling munmap between
	 * allocation and now, or the NULL bucket above -- does not
	 * SIGSEGV the sanitiser inside poison_output_struct's
	 * byte-walk; range_readable_user() also rejects NULL, so the
	 * ~30% NULL bucket above skips poison naturally without a
	 * separate guard.  On skip, poison_seed stays 0 and the post
	 * handler no-ops the untouched-buffer check.  Done after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see.
	 */
	{
		void *buf = (void *)(unsigned long) rec->a1;

		if (range_readable_user(buf, sizeof(time_t)))
			snap->poison_seed = poison_output_struct(buf,
								 sizeof(time_t),
								 0);
	}
	post_state_install(rec, snap);
}

/*
 * Oracle: sys_time returns current wall-clock time in seconds since the
 * Epoch -- the same value we get from clock_gettime(CLOCK_REALTIME).
 * Both are ultimately served by the same timekeeping subsystem, so a
 * meaningful divergence between the two reads taken back-to-back from
 * userspace points at a real ABI break: a sign-extension bug in the
 * compat path, a 32-bit y2038 wrap, a tloc-copy-back that wrote stale
 * stack, or the syscall returning a cached value from a stale vsyscall
 * page after a clock-jump.
 *
 * Tolerance is +/-5 seconds.  The two reads aren't atomic with respect
 * to each other: scheduler delay between sys_time returning and us
 * calling clock_gettime, plus NTP slew across the gap, can legitimately
 * shift the second sample by a second or two.  A real ABI break
 * (truncation, wrap, sign extension) puts the values days or years
 * apart, well outside this window.
 *
 * Sample only successful returns; sanitised tloc pointers can produce
 * -EFAULT and that's not an oracle violation.  ONE_IN(100) keeps the
 * extra clock_gettime cost in line with the rest of the oracle family.
 * The untouched-buffer poison check runs on every success (no ONE_IN
 * gate) because it is an 8-byte memcmp with no syscall re-issue.
 */
static void post_time(struct syscallrecord *rec)
{
	struct time_post_state *snap;
	struct timespec ts;
	unsigned long retval;
	long syscall_t, real_t, diff;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, TIME_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	/*
	 * Snapshot rec->retval once.  rec lives in the child's shm region;
	 * reading it at the IS_ERR_VALUE guard and again at the cast to
	 * signed wall-clock leaves a window in which a sibling-child stomp
	 * or a signal-handler reschedule can rewrite the slot between the
	 * two reads, so the errno-range guard could pass on the original
	 * negative-but-errno value while the second read sees a stomped
	 * non-errno value that survives the syscall_t <= 0 check, producing
	 * a false oracle fire on a memory-corruption shape rather than a
	 * real kernel ABI break.  Same multi-read shape the epoll
	 * post-handlers had (commit 48279ed126bb).
	 */
	retval = rec->retval;
	syscall_t = (long) retval;

	/* Errno-style return (-1..-MAX_ERRNO): silent skip.  Sanitised
	 * tloc producing -EFAULT is normal and not an oracle violation. */
	if (IS_ERR_VALUE(retval))
		goto out_release;

	/*
	 * Untouched-buffer check: time returned a non-error epoch value
	 * but the user time_t still byte-for-byte matches the poison
	 * pattern we stamped at sanitise time -- the kernel never called
	 * copy_to_user() at all.  Runs on every success (no ONE_IN gate)
	 * because the check is an 8-byte memcmp with no re-issue, so it
	 * stays cheap enough to fire every time; bumps the shared
	 * post_handler_untouched_out_buf slot.  Skip when poison_seed is
	 * 0: sanitise refused to stamp (NULL or unmapped tloc) so there
	 * is no pattern to compare against.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->tloc,
					     sizeof(time_t), snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_release;

	/* A successful sys_time() must be a positive wall-clock time.
	 * Zero means the Epoch and a negative value outside the errno
	 * range cannot be a real time post-1970 -- both shapes point at
	 * a sign-extension bug on the compat path, a 32-bit y2038 wrap,
	 * or a tloc-copy-back that returned stale stack. */
	if (syscall_t <= 0) {
		output(0, "time oracle: non-positive successful return %ld\n",
		       syscall_t);
		__atomic_add_fetch(&shm->stats.oracle.time_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		goto out_release;
	}

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		goto out_release;

	real_t = (long) ts.tv_sec;
	diff = syscall_t - real_t;

	if (diff < -5 || diff > 5) {
		output(0, "time oracle: returned %ld but clock_gettime=%ld (diff=%ld)\n",
		       syscall_t, real_t, diff);
		__atomic_add_fetch(&shm->stats.oracle.time_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_time = {
	.name = "time",
	.group = GROUP_TIME,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tloc" },
	.sanitise = sanitise_time,
	.post = post_time,
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
};
