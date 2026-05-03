/*
   long sys_sigaltstack(const stack_t __user *uss, stack_t __user *uoss)
 */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

#if defined(SYS_sigaltstack) || defined(__NR_sigaltstack)
#ifndef SYS_sigaltstack
#define SYS_sigaltstack __NR_sigaltstack
#endif
#define HAVE_SYS_SIGALTSTACK 1
#endif

static void sanitise_sigaltstack(struct syscallrecord *rec)
{
	stack_t *ss;

	ss = (stack_t *) get_writable_address(sizeof(*ss));

	switch (rand() % 5) {
	case 0: /* disable the signal stack */
		ss->ss_sp = NULL;
		ss->ss_flags = SS_DISABLE;
		ss->ss_size = 0;
		break;
	case 1:	/* minimum size */
		ss->ss_sp = (void *) get_writable_address(MINSIGSTKSZ);
		ss->ss_flags = 0;
		ss->ss_size = MINSIGSTKSZ;
		break;
	case 2: /* common size (8 pages) */
		ss->ss_sp = (void *) get_writable_address(page_size * 8);
		ss->ss_flags = 0;
		ss->ss_size = page_size * 8;
		break;
	case 3: /* autodisarm */
		ss->ss_sp = (void *) get_writable_address(SIGSTKSZ);
		ss->ss_flags = SS_AUTODISARM;
		ss->ss_size = SIGSTKSZ;
		break;
	default: /* boundary: too small */
		ss->ss_sp = (void *) get_writable_address(page_size);
		ss->ss_flags = RAND_BOOL() ? SS_AUTODISARM : 0;
		ss->ss_size = rand() % MINSIGSTKSZ;
		break;
	}

	rec->a1 = (unsigned long) ss;

	/*
	 * uoss (a2) is the kernel's writeback target for the previous stack:
	 * the kernel fills its three fields when uoss is non-NULL.
	 * ARG_ADDRESS draws from the random pool, so a fuzzed pointer can
	 * land inside an alloc_shared region.
	 */
	avoid_shared_buffer(&rec->a2, sizeof(stack_t));
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
 * TOCTOU defeat: snapshot the stack_t payload into a stack-local BEFORE
 * re-issuing, so a sibling that scribbles either rec->a2 or the user buffer
 * between syscall return and the post hook cannot smear the comparison.
 * The re-call uses a fresh stack buffer (NOT rec->a2 -- a sibling could
 * mutate it mid-syscall and forge a clean compare).
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
	stack_t first_ss;
	stack_t recheck_ss;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a1 != 0)
		return;

	if (rec->a2 == 0)
		return;

	{
		void *uoss = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a2. */
		if (looks_like_corrupted_ptr(uoss)) {
			outputerr("post_sigaltstack: rejected suspicious uoss=%p (pid-scribbled?)\n",
				  uoss);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&first_ss, (const void *)(unsigned long) rec->a2,
	       sizeof(first_ss));

	memset(&recheck_ss, 0, sizeof(recheck_ss));
	rc = syscall(SYS_sigaltstack, NULL, &recheck_ss);
	if (rc != 0)
		return;

	if (first_ss.ss_sp != recheck_ss.ss_sp) {
		output(0,
		       "[oracle:sigaltstack] ss_sp %p vs %p\n",
		       first_ss.ss_sp, recheck_ss.ss_sp);
		__atomic_add_fetch(&shm->stats.sigaltstack_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (first_ss.ss_flags != recheck_ss.ss_flags &&
	    recheck_ss.ss_flags != (first_ss.ss_flags | SS_DISABLE)) {
		output(0,
		       "[oracle:sigaltstack] ss_flags 0x%x vs 0x%x\n",
		       (unsigned int) first_ss.ss_flags,
		       (unsigned int) recheck_ss.ss_flags);
		__atomic_add_fetch(&shm->stats.sigaltstack_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (first_ss.ss_size != recheck_ss.ss_size) {
		output(0,
		       "[oracle:sigaltstack] ss_size %zu vs %zu\n",
		       (size_t) first_ss.ss_size,
		       (size_t) recheck_ss.ss_size);
		__atomic_add_fetch(&shm->stats.sigaltstack_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}
#endif

struct syscallentry syscall_sigaltstack = {
	.name = "sigaltstack",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [1] = ARG_ADDRESS },
	.argname = { [0] = "uss", [1] = "uoss" },
	.sanitise = sanitise_sigaltstack,
#ifdef HAVE_SYS_SIGALTSTACK
	.post = post_sigaltstack,
#endif
};
