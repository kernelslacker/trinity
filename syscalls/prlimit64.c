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
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

#if defined(SYS_prlimit64) || defined(__NR_prlimit64)
#ifndef SYS_prlimit64
#define SYS_prlimit64 __NR_prlimit64
#endif
#define HAVE_SYS_PRLIMIT64 1
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
 * TOCTOU defeat: snapshot all four args plus the rlimit64 payload into
 * stack-locals BEFORE re-issuing, so a sibling that scribbles either
 * rec->aN or the user buffer between syscall return and the post hook
 * cannot smear the comparison.  The re-call uses a fresh stack buffer
 * (NOT rec->a4 -- a sibling could mutate it mid-syscall and forge a clean
 * compare).
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
	struct rlimit64 first_rlim;
	struct rlimit64 recheck_rlim;
	pid_t pid_snap;
	unsigned int resource_snap;
	long rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a3 != 0)
		return;

	if (rec->a4 == 0)
		return;

	pid_snap      = (pid_t) rec->a1;
	resource_snap = (unsigned int) rec->a2;

	if (pid_snap != 0 && pid_snap != (pid_t) syscall(SYS_gettid))
		return;

	if (resource_snap >= RLIMIT_NLIMITS)
		return;

	memcpy(&first_rlim, (const void *)(unsigned long) rec->a4,
	       sizeof(first_rlim));

	memset(&recheck_rlim, 0, sizeof(recheck_rlim));
	rc = syscall(SYS_prlimit64, pid_snap, resource_snap, NULL,
		     &recheck_rlim);
	if (rc != 0)
		return;

	if (first_rlim.rlim_cur != recheck_rlim.rlim_cur) {
		output(0,
		       "[oracle:prlimit64] rlim_cur %llu vs %llu (resource=%u)\n",
		       (unsigned long long) first_rlim.rlim_cur,
		       (unsigned long long) recheck_rlim.rlim_cur,
		       resource_snap);
		__atomic_add_fetch(&shm->stats.prlimit64_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	if (first_rlim.rlim_max != recheck_rlim.rlim_max) {
		output(0,
		       "[oracle:prlimit64] rlim_max %llu vs %llu (resource=%u)\n",
		       (unsigned long long) first_rlim.rlim_max,
		       (unsigned long long) recheck_rlim.rlim_max,
		       resource_snap);
		__atomic_add_fetch(&shm->stats.prlimit64_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
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
