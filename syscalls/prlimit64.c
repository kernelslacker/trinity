/*
 * SYSCALL_DEFINE4(prlimit64, pid_t, pid, unsigned int, resource,
	 const struct rlimit64 __user *, new_rlim,
	 struct rlimit64 __user *, old_rlim)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if defined(SYS_prlimit64) || defined(__NR_prlimit64)
#ifndef SYS_prlimit64
#define SYS_prlimit64 __NR_prlimit64
#endif
#define HAVE_SYS_PRLIMIT64 1
#endif

#ifdef HAVE_SYS_PRLIMIT64
/*
 * Snapshot of the four prlimit64 input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the oracle at a foreign old_rlim
 * buffer, retarget the pid self-filter, or smear the resource bound
 * used to gate the re-issue.
 */
struct prlimit64_post_state {
	unsigned long pid;
	unsigned long resource;
	unsigned long new_rlim;
	unsigned long old_rlim;
};
#endif

static unsigned long rlimit_resources[] = {
	RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK,
	RLIMIT_CORE, RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE,
	RLIMIT_MEMLOCK, RLIMIT_AS, RLIMIT_LOCKS, RLIMIT_SIGPENDING,
	RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_RTPRIO,
};

static rlim64_t random_rlim64(void)
{
	switch (rand() % 5) {
	case 0: return RLIM64_INFINITY;
	case 1: return 0;
	case 2: return 1 + (rand() % 1024);
	case 3: return (rlim64_t) page_size * (1 + (rand() % 256));
	default: return rand32();
	}
}

/* Fill struct rlimit64 with interesting boundary values. */
static void sanitise_prlimit64(struct syscallrecord *rec)
{
	struct rlimit64 *rlim;
#ifdef HAVE_SYS_PRLIMIT64
	struct prlimit64_post_state *snap;

	rec->post_state = 0;
#endif

	rlim = (struct rlimit64 *) get_writable_address(sizeof(*rlim));
	rlim->rlim_cur = random_rlim64();
	rlim->rlim_max = random_rlim64();

	/* Half the time, enforce cur <= max for valid calls. */
	if (RAND_BOOL() && rlim->rlim_cur > rlim->rlim_max)
		rlim->rlim_cur = rlim->rlim_max;

	rec->a3 = (unsigned long) rlim;

	/*
	 * old_rlim (a4) is the kernel's writeback target for the previous
	 * limit values: ARG_ADDRESS draws from the random pool, so a fuzzed
	 * pointer can land inside an alloc_shared region.  Scrub it.
	 */
	avoid_shared_buffer(&rec->a4, sizeof(struct rlimit64));

#ifdef HAVE_SYS_PRLIMIT64
	/*
	 * Snapshot the four input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original
	 * old_rlim pointer, the pid self-filter would resolve against a
	 * scribbled value, and the resource bound check could be smeared
	 * past RLIMIT_NLIMITS.  post_state is private to the post handler.
	 * Gated on HAVE_SYS_PRLIMIT64 to mirror the .post registration --
	 * on systems without SYS_prlimit64 the post handler is not
	 * registered and a snapshot only the post handler can free would
	 * leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->pid       = rec->a1;
	snap->resource  = rec->a2;
	snap->new_rlim  = rec->a3;
	snap->old_rlim  = rec->a4;
	rec->post_state = (unsigned long) snap;
#endif
}

/*
 * Oracle: prlimit64(pid, resource, new_rlim, old_rlim) has two modes.
 * When new_rlim != NULL the call MUTATES task->signal->rlim[resource], so
 * a re-issue equality check is meaningless.  When new_rlim == NULL the
 * call is a pure read of the current (rlim_cur, rlim_max) pair, sourced
 * from task->signal->rlim[] under task_lock; for a self-target (pid == 0
 * or pid == gettid()) the only mutator is a parallel prlimit64 / setrlimit
 * against ourselves -- a same-task re-issue ~150ms later through the same
 * code path must produce a byte-identical (rlim_cur, rlim_max) pair unless
 * one of:
 *
 *   - copy_to_user mis-write past or before the rlimit64 user slot.
 *   - 32-on-64 compat sign-extension on either 64-bit limit field.
 *   - Torn write from a parallel setrlimit/prlimit64 against ourselves
 *     (cred_guard_mutex starvation lets two writers interleave).
 *   - Stale rcu read of task->signal after a parallel exec walked through
 *     setup_new_exec()/credential install.
 *   - Sibling-thread scribble of either rec->aN or the user buffer between
 *     syscall return and our post-hook re-read.
 *
 * Mode A (new_rlim != NULL) is gated out by the rec->a3 != 0 check: the
 * sanitiser always wires a non-NULL rlim into a3 today, but if a future
 * sanitiser revision starts emitting mode-B calls the oracle picks them up
 * automatically.  Other-pid targets (pid != 0 && pid != gettid()) are
 * gated out -- another task's limits can be legitimately mutated by a
 * sibling between our two reads, which would surface as a benign
 * divergence storm.  RLIMIT_NLIMITS is checked defensively in case a
 * future kernel/glibc adds resource constants the sanitiser table does not
 * yet know about.
 *
 * TOCTOU defeat: the four input args (pid, resource, new_rlim, old_rlim)
 * are snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot redirect the oracle at a foreign old_rlim, retarget the
 * pid self-filter, or smear the resource bound that gates the re-issue.
 * The rlimit64 payload at *old_rlim is then snapshotted into a stack-local
 * before re-issuing, and the re-call writes into a fresh private stack
 * buffer (NOT the snapshot's old_rlim -- a sibling could mutate the user
 * buffer itself mid-syscall and forge a clean compare).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  Per-field bumps with no early-return so simultaneous
 * rlim_cur+rlim_max corruption surfaces in a single sample.
 *
 * False-positive sources at ONE_IN(100):
 *   - Sibling prlimit64(self, ..., new_rlim != NULL, ...) between the two
 *     reads: rc != 0 path swallows the common case (concurrent prlimit on
 *     self serialises through task->signal->cred_guard_mutex and one of
 *     the two reads will see EAGAIN/EPERM).  When BOTH reads succeed and
 *     diverge, that is a real signal of cred-mutex starvation.
 *   - Resource not supported by kernel: returns -EINVAL on the first call,
 *     swallowed by the retval != 0 gate.
 *   - Defensive RLIMIT_NLIMITS bail covers any future RLIMIT_* enum drift.
 */
#ifdef HAVE_SYS_PRLIMIT64
static void post_prlimit64(struct syscallrecord *rec)
{
	struct prlimit64_post_state *snap =
		(struct prlimit64_post_state *) rec->post_state;
	struct rlimit64 first_rlim;
	struct rlimit64 recheck_rlim;
	long rc;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_prlimit64: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->new_rlim != 0)
		goto out_free;

	if (snap->old_rlim == 0)
		goto out_free;

	if (snap->pid != 0 &&
	    snap->pid != (unsigned long) syscall(SYS_gettid))
		goto out_free;

	if (snap->resource >= RLIMIT_NLIMITS)
		goto out_free;

	{
		void *old_rlim = (void *)(unsigned long) snap->old_rlim;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner
		 * old_rlim pointer field.  Reject pid-scribbled old_rlim
		 * before deref.
		 */
		if (looks_like_corrupted_ptr(old_rlim)) {
			outputerr("post_prlimit64: rejected suspicious old_rlim=%p (post_state-scribbled?)\n",
				  old_rlim);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	memcpy(&first_rlim, (const void *)(unsigned long) snap->old_rlim,
	       sizeof(first_rlim));

	memset(&recheck_rlim, 0, sizeof(recheck_rlim));
	rc = syscall(SYS_prlimit64, (pid_t) snap->pid,
		     (unsigned int) snap->resource, NULL, &recheck_rlim);
	if (rc != 0)
		goto out_free;

	if (first_rlim.rlim_cur != recheck_rlim.rlim_cur) {
		output(0,
		       "[oracle:prlimit64] rlim_cur %llu vs %llu (resource=%u)\n",
		       (unsigned long long) first_rlim.rlim_cur,
		       (unsigned long long) recheck_rlim.rlim_cur,
		       (unsigned int) snap->resource);
		__atomic_add_fetch(&shm->stats.prlimit64_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (first_rlim.rlim_max != recheck_rlim.rlim_max) {
		output(0,
		       "[oracle:prlimit64] rlim_max %llu vs %llu (resource=%u)\n",
		       (unsigned long long) first_rlim.rlim_max,
		       (unsigned long long) recheck_rlim.rlim_max,
		       (unsigned int) snap->resource);
		__atomic_add_fetch(&shm->stats.prlimit64_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif

struct syscallentry syscall_prlimit64 = {
	.name = "prlimit64",
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_OP, [3] = ARG_ADDRESS },
	.argname = { [0] = "pid", [1] = "resource", [2] = "new_rlim", [3] = "old_rlim" },
	.arg_params[1].list = ARGLIST(rlimit_resources),
	.group = GROUP_PROCESS,
	.sanitise = sanitise_prlimit64,
#ifdef HAVE_SYS_PRLIMIT64
	.post = post_prlimit64,
#endif
};
