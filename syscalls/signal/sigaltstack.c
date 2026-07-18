/*
   long sys_sigaltstack(const stack_t __user *uss, stack_t __user *uoss)
 */
#include <signal.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "maps.h"
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/signal.h"
#if defined(SYS_sigaltstack) || defined(__NR_sigaltstack)
#ifndef SYS_sigaltstack
#define SYS_sigaltstack __NR_sigaltstack
#endif
#define HAVE_SYS_SIGALTSTACK 1
#endif

#ifdef HAVE_SYS_SIGALTSTACK
/*
 * Snapshot of the two sigaltstack input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot flip the mode-A gate (uss == NULL) into a
 * spurious oracle run, nor can it redirect the uoss read at a foreign
 * stack_t buffer.
 */
#define SIGALTSTACK_POST_STATE_MAGIC	0x53415354UL	/* "SAST" */
struct sigaltstack_post_state {
	unsigned long magic;
	unsigned long uss;
	unsigned long uoss;
	/*
	 * Seed for the poison pattern stamped into the uoss stack_t buffer
	 * at sanitise time.  Fed back into check_output_struct() in the
	 * post handler on the syscall's real success gate: a byte-identical
	 * poison after retval == 0 with uoss != NULL means the kernel
	 * returned success without writing the old-stack fields.  A seed
	 * of 0 means sanitise refused to stamp (uoss == NULL, or a
	 * writable-pool draw that avoid_shared_buffer_out relocated to an
	 * address that is no longer provably readable) and the post check
	 * no-ops -- independent of the mode-B (snap->uss == 0) field-diff
	 * oracle, which continues to run under its own gate.
	 */
	uint64_t poison_seed;
};
#endif

static void sanitise_sigaltstack(struct syscallrecord *rec)
{
	stack_t *ss;
	unsigned int draw;
	static long min_ss;
#ifdef HAVE_SYS_SIGALTSTACK
	struct sigaltstack_post_state *snap;
#endif

	/*
	 * Static MINSIGSTKSZ (a build-time macro, 2KB on x86_64 glibc)
	 * undersizes the "valid" altstack bucket on CPUs with large xstate
	 * (AMX etc.), so signal delivery on those hosts overflows the stack
	 * instead of exercising the successful-delivery path.  Cache the
	 * dynamic floor from sysconf(_SC_MINSIGSTKSZ) on first use, clamped
	 * up by the static macro in case sysconf returns something absurd.
	 * On old glibc where the sysconf key is unavailable, fall back to a
	 * generous static floor comfortably above any current xstate size.
	 */
	if (min_ss == 0) {
#ifdef _SC_MINSIGSTKSZ
		long v = sysconf(_SC_MINSIGSTKSZ);
		min_ss = (v > (long) MINSIGSTKSZ) ? v : (long) MINSIGSTKSZ;
#else
		min_ss = 16 * 1024;
#endif
	}

	/*
	 * Shape distribution (approximate):
	 *   30% enabled  (ss_flags=0, valid sp, size min_ss*(1..4))
	 *   20% disabled (SS_DISABLE, NULL sp, size 0)
	 *   15% too-small (size < min_ss -- kernel EINVAL gate)
	 *   10% misaligned sp (kernel behaviour varies, validation stays warm)
	 *   15% SS_AUTODISARM (explicit bucket so disarm-on-handler-entry
	 *                      and re-arm-on-handler-exit paths actually fire)
	 *   10% NULL ss     (getter-only call -- legal, kernel just reports
	 *                    current; mode-B for the post oracle)
	 */
	draw = rnd_modulo_u32(100);

	if (draw < 10) {
		/* getter-only: leave uss = NULL, post oracle picks this up
		 * via the snap->uss == 0 mode-B gate. */
		rec->a1 = 0;
		goto choose_uoss;
	}

	ss = (stack_t *) get_writable_address(sizeof(*ss));
	if (ss == NULL) {
		rec->post_state = 0;
		return;
	}

	/*
	 * Zero the whole struct so any inter-field pad (e.g. the 4-byte
	 * gap between ss_flags and ss_size on LP64) is initialised before
	 * the kernel copies sizeof(stack_t) from userspace.
	 */
	memset(ss, 0, sizeof(*ss));

	if (draw < 40) {
		/* enabled: min_ss * (1..4) */
		unsigned int mult = 1 + rnd_modulo_u32(4);
		size_t sz = (size_t) min_ss * mult;
		ss->ss_sp = (void *) get_writable_address(sz);
		ss->ss_flags = 0;
		ss->ss_size = sz;
	} else if (draw < 60) {
		/* disabled */
		ss->ss_sp = NULL;
		ss->ss_flags = SS_DISABLE;
		ss->ss_size = 0;
	} else if (draw < 75) {
		/* too-small: kernel must reject with EINVAL */
		ss->ss_sp = (void *) get_writable_address(page_size);
		ss->ss_flags = RAND_BOOL() ? SS_AUTODISARM : 0;
		ss->ss_size = rnd_modulo_u32((unsigned int) min_ss);
	} else if (draw < 85) {
		/* misaligned ss_sp: nudge a valid allocation by an odd
		 * byte offset.  The base allocation is sized to absorb the
		 * nudge so we are still pointing inside writable memory. */
		unsigned char *base = (unsigned char *) get_writable_address((size_t) min_ss + 16);
		unsigned int nudge = 1 + rnd_modulo_u32(7);
		ss->ss_sp = base ? (void *) (base + nudge) : NULL;
		ss->ss_flags = 0;
		ss->ss_size = min_ss;
	} else {
		/* SS_AUTODISARM (kernel >= 4.7) */
		ss->ss_sp = (void *) get_writable_address(SIGSTKSZ);
		ss->ss_flags = SS_AUTODISARM;
		ss->ss_size = SIGSTKSZ;
	}

	rec->a1 = (unsigned long) ss;
	avoid_shared_buffer_inout(&rec->a1, sizeof(stack_t));

choose_uoss:
	/*
	 * uoss (a2) is the kernel's writeback target for the previous stack:
	 * the kernel fills its three fields when uoss is non-NULL.
	 * ARG_ADDRESS draws from the random pool, so a fuzzed pointer can
	 * land inside an alloc_shared region.  Force ~30% NULL so the
	 * "don't bother reporting old stack" path is actually exercised.
	 */
	if (rnd_modulo_u32(10) < 3)
		rec->a2 = 0;
	avoid_shared_buffer_out(&rec->a2, sizeof(stack_t));

#ifdef HAVE_SYS_SIGALTSTACK
	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->a1/a2 at post-time, when a sibling
	 * syscall may have scribbled the slots: a flipped a1 could turn a
	 * mode-A call (uss != NULL, mutates state) into a spurious mode-B
	 * oracle run, and looks_like_corrupted_ptr() cannot tell a
	 * real-but-wrong heap address from the original uoss buffer.
	 * post_state is private to the post handler.  Gated on
	 * HAVE_SYS_SIGALTSTACK to mirror the .post registration -- on
	 * systems without SYS_sigaltstack the post handler is not
	 * registered and a snapshot only the post handler can free would
	 * leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SIGALTSTACK_POST_STATE_MAGIC;
	snap->uss   = rec->a1;
	snap->uoss  = rec->a2;
	/*
	 * Stamp a per-call poison pattern into the uoss user buffer the
	 * kernel is about to fill on this success path.  The post handler
	 * feeds the seed back into check_output_struct(); a byte-identical
	 * poison after a 0-retval means the kernel skipped the old-stack
	 * writeback entirely.  Two gates before stamping:
	 *
	 *   - uoss == NULL: ~30% of calls force uoss = 0 as the "don't
	 *     bother reporting old stack" arm.  The kernel contract there
	 *     is to not touch the buffer, so there is nothing to poison
	 *     and nothing to check.  poison_seed stays 0.
	 *
	 *   - range_readable_user(): a writable-pool draw that
	 *     avoid_shared_buffer_out() relocated to an address no longer
	 *     provably mapped (e.g. sibling munmap between allocation and
	 *     now) must not SIGSEGV the sanitiser inside
	 *     poison_output_struct's byte-walk.
	 *
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see.
	 */
	{
		void *uoss_buf = (void *)(unsigned long) rec->a2;

		if (uoss_buf != NULL &&
		    range_readable_user(uoss_buf, sizeof(stack_t)))
			snap->poison_seed = poison_output_struct(uoss_buf,
								 sizeof(stack_t),
								 0);
	}
	/*
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_sigaltstack() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	post_state_install(rec, snap);
#endif
}

/*
 * Oracle: sigaltstack(uss, uoss) has two modes.  When uss != NULL the call
 * MUTATES task->sas_ss_sp / sas_ss_size / sas_ss_flags, so a re-issue
 * equality check is meaningless.  When uss == NULL && uoss != NULL the call
 * is a pure read of the current alt-stack (ss_sp, ss_flags, ss_size) sourced
 * from the calling task's sighand-protected sas_ss_* fields; the only
 * mutators against ourselves are a parallel sigaltstack(uss != NULL) on the
 * same task, signal-handler entry/exit on an SS_AUTODISARM stack, or exec.
 * A same-task re-issue ~150ms later through the same code path must produce
 * a byte-identical (ss_sp, ss_flags, ss_size) triple unless one of:
 *
 *   - copy_to_user mis-write past or before the stack_t user slot.
 *   - 32-on-64 compat sign-extension on ss_size or pointer truncation on
 *     ss_sp.
 *   - Torn write from a parallel sigaltstack(uss != NULL) against ourselves
 *     (sighand_lock starvation lets two writers interleave).
 *   - Stale rcu read of task->sas_ss_* after a parallel exec walked through
 *     setup_new_exec()/restore_altstack().
 *   - Sibling-thread scribble of either rec->aN or the user buffer between
 *     syscall return and our post-hook re-read.
 *
 * Mode A (uss != NULL) is gated out by the rec->a1 != 0 check: the
 * sanitiser always wires a non-NULL ss into a1 today, but if a future
 * sanitiser revision starts emitting mode-B calls the oracle picks them up
 * automatically.
 *
 * TOCTOU defeat: the two input args (uss, uoss) are snapshotted at
 * sanitise time into a heap struct in rec->post_state, so a sibling that
 * scribbles rec->aN between syscall return and post entry cannot flip
 * the mode-A gate or redirect the uoss read at a foreign stack_t.  We
 * still snapshot the stack_t payload into a stack-local BEFORE
 * re-issuing, so a sibling that scribbles the user buffer itself between
 * the two reads cannot smear the comparison.  The re-call uses a fresh
 * stack buffer (NOT the snap's uoss -- a sibling could mutate the user
 * buffer mid-syscall and forge a clean compare).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  Per-field bumps with no early-return so simultaneous
 * ss_sp+ss_flags+ss_size corruption surfaces in a single sample.
 *
 * False-positive sources at ONE_IN(100):
 *   - Sibling sigaltstack(uss != NULL) against self between the two reads:
 *     when both reads succeed and diverge that IS a real signal we want.
 *     When the recheck fails (e.g. -EPERM mid-handler), rc != 0 swallows.
 *   - Signal delivery between the two reads on a stack with SS_AUTODISARM:
 *     the kernel sets SS_DISABLE on handler entry and clears it on
 *     handler return when SS_AUTODISARM was set.  The window between our
 *     two reads can catch SS_DISABLE briefly -- whitelisted via the
 *     (orig | SS_DISABLE) gate below.
 *   - 32-on-64 compat builds: stack_t has no end-of-struct pad on
 *     x86_64/aarch64, but a defensive memset of recheck_ss before re-issue
 *     handles any future ABI surprise.
 */
#ifdef HAVE_SYS_SIGALTSTACK
static void post_sigaltstack(struct syscallrecord *rec)
{
	struct sigaltstack_post_state *snap;
	stack_t first_ss;
	stack_t recheck_ss;
	long rc;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, SIGALTSTACK_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_free;

	/*
	 * Untouched-buffer poison check: sigaltstack returned 0 with a
	 * non-NULL uoss but the user buffer still byte-for-byte matches
	 * the poison pattern we stamped at sanitise time -- the kernel
	 * never wrote back the old stack_t.  Runs on every success path
	 * where poison actually got stamped (no ONE_IN gate) because the
	 * check is a sizeof(stack_t) memcmp with no syscall re-issue, and
	 * it is independent of the mode-B (snap->uss == 0) field-diff
	 * oracle below -- a mode-A caller that supplies uoss also gets
	 * the writeback contract, so limiting the check to mode-B would
	 * miss the broader class.  Skip when poison_seed is 0: sanitise
	 * refused to stamp (uoss == NULL or unmapped) so there is no
	 * pattern to compare against.
	 */
	if (snap->uoss != 0 && snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->uoss,
					     sizeof(stack_t),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

	if (!ONE_IN(100))
		goto out_free;

	if (snap->uss != 0)
		goto out_free;

	if (snap->uoss == 0)
		goto out_free;

	if (!post_snapshot_or_skip(&first_ss,
				   (const void *)(unsigned long) snap->uoss,
				   sizeof(first_ss)))
		goto out_free;

	memset(&recheck_ss, 0, sizeof(recheck_ss));
	rc = syscall(SYS_sigaltstack, NULL, &recheck_ss);
	if (rc != 0)
		goto out_free;

	if (first_ss.ss_sp != recheck_ss.ss_sp) {
		output(0,
		       "[oracle:sigaltstack] ss_sp %p vs %p\n",
		       first_ss.ss_sp, recheck_ss.ss_sp);
		__atomic_add_fetch(&shm->stats.oracle.sigaltstack_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (first_ss.ss_flags != recheck_ss.ss_flags &&
	    recheck_ss.ss_flags != (first_ss.ss_flags | SS_DISABLE)) {
		output(0,
		       "[oracle:sigaltstack] ss_flags 0x%x vs 0x%x\n",
		       (unsigned int) first_ss.ss_flags,
		       (unsigned int) recheck_ss.ss_flags);
		__atomic_add_fetch(&shm->stats.oracle.sigaltstack_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (first_ss.ss_size != recheck_ss.ss_size) {
		output(0,
		       "[oracle:sigaltstack] ss_size %zu vs %zu\n",
		       (size_t) first_ss.ss_size,
		       (size_t) recheck_ss.ss_size);
		__atomic_add_fetch(&shm->stats.oracle.sigaltstack_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	post_state_release(rec, snap);
}
#endif

struct syscallentry syscall_sigaltstack = {
	.name = "sigaltstack",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "uss", [1] = "uoss" },
	.sanitise = sanitise_sigaltstack,
#ifdef HAVE_SYS_SIGALTSTACK
	.post = post_sigaltstack,
#endif
	.rettype = RET_ZERO_SUCCESS,
};
