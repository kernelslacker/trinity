/*
 * SYSCALL_DEFINE3(sigprocmask, int, how, old_sigset_t __user *, set,
		 old_sigset_t __user *, oset)
 */
#include <signal.h>
#include <stdint.h>
#include "output-poison.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long sigprocmask_how[] = {
	SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK,
};

/*
 * Snapshot of the sigprocmask oset pointer plus the poison seed read by
 * the post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->a3 between the syscall
 * returning and the post handler running cannot redirect the poison
 * check against an unrelated heap page whose residual bytes happen to
 * still match some earlier call's seed.  A poison_seed of 0 means the
 * sanitise-time writability check refused to stamp poison for this
 * call (ARG_ADDRESS handed back NULL, or the writable draw was no
 * longer provably mapped) and the post handler must no-op the
 * untouched-buffer arm.
 */
#define SIGPROCMASK_POST_STATE_MAGIC	0x53504D4BUL	/* "SPMK" */
struct sigprocmask_post_state {
	unsigned long magic;
	unsigned long oset;
	uint64_t poison_seed;
};

static void sanitise_sigprocmask(struct syscallrecord *rec)
{
	struct sigprocmask_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * oset (a3) is the kernel's writeback target for the previous mask.
	 * sigprocmask predates rt_sigprocmask and uses old_sigset_t, which
	 * is one word; sigset_t is the conservative upper bound.
	 */
	avoid_shared_buffer_out(&rec->a3, sizeof(sigset_t));

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SIGPROCMASK_POST_STATE_MAGIC;
	snap->oset  = rec->a3;

	/*
	 * Stamp a per-call poison pattern into the output buffer the
	 * kernel is about to fill.  CRITICAL: the poison window is
	 * exactly sizeof(unsigned long) == old_sigset_t (8 bytes on
	 * x86_64), NOT sizeof(sigset_t).  avoid_shared_buffer_out above
	 * bounds the writable draw at the larger sigset_t width, but the
	 * kernel only writes the leading old_sigset_t word -- a wider
	 * poison window would leave the unwritten tail intact and false-
	 * positive on every success return.  range_readable_user() folds
	 * both the NULL gate (oset is ARG_ADDRESS, so a3 == 0 is a
	 * documented "don't write back") and the unmapped-address gate
	 * into one call: NULL and unproven ranges both return false, so
	 * poison_seed stays 0 and the post handler no-ops.  Done after
	 * avoid_shared_buffer_out() so the poison lands on the final
	 * buffer the kernel will see.
	 */
	buf = (void *)(unsigned long) rec->a3;
	if (range_readable_user(buf, sizeof(unsigned long)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(unsigned long),
							 0);

	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_sigprocmask() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
}

/*
 * Oracle: sigprocmask(how, set, oset) sets the calling thread's signal
 * block mask and, if oset != NULL, writes the previous mask to *oset as
 * a single old_sigset_t word.  On retval == 0 with a non-NULL oset the
 * kernel is contracted to overwrite that word.  This entry point is the
 * i386 compat path (x86_64 uses rt_sigprocmask, which carries its own
 * poison oracle) so a byte-identical poison after success on a non-NULL
 * oset means the compat copy_to_user() path was skipped entirely; bump
 * the shared post_handler_untouched_out_buf counter.
 */
static void post_sigprocmask(struct syscallrecord *rec)
{
	struct sigprocmask_post_state *snap;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SIGPROCMASK_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	/*
	 * Untouched-buffer check: sigprocmask returned 0 with a non-NULL
	 * oset, but the leading old_sigset_t word still matches the
	 * poison pattern we stamped at sanitise time -- the compat
	 * copy_to_user() path never landed the previous block mask.
	 * Window is exactly sizeof(unsigned long) == old_sigset_t, not
	 * the sigset_t upper bound used by avoid_shared_buffer_out()
	 * (that width would leave the unwritten tail and false-positive
	 * every success).  Cheap: single-word memcmp, no re-issue, so
	 * runs on every success rather than under ONE_IN().  A
	 * poison_seed of 0 is the sanitise-refused-to-stamp signal (NULL
	 * oset or unmapped writable draw) -- gating on it here also
	 * doubles as the NULL-oset short-circuit, so no separate
	 * snap->oset == 0 check is needed above.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->oset,
					     sizeof(unsigned long),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_sigprocmask = {
	.name = "sigprocmask",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "how", [1] = "set", [2] = "oset" },
	.arg_params[0].list = ARGLIST(sigprocmask_how),
	.sanitise = sanitise_sigprocmask,
	.post = post_sigprocmask,
	.rettype = RET_ZERO_SUCCESS,
};
