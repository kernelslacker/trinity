/*
 * SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

static unsigned long getrlimit_resources[] = {
	RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA,
	RLIMIT_FSIZE, RLIMIT_LOCKS, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE,
	RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS,
	RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK,
};

static void sanitise_getrlimit(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(struct rlimit));
}

/*
 * Oracle: getrlimit(resource, &rlim) reads task->signal->rlim[resource]
 * under task_lock and copies the {rlim_cur, rlim_max} pair out to the
 * user buffer.  Re-issuing the same query for the same resource a moment
 * later must produce the same pair unless something in between either
 * (a) had copy_to_user write past or before the live rlim slot, (b) tore
 * a write from a parallel prlimit64 setting our own limits, or (c) the
 * userspace receive buffer was clobbered after the kernel returned.
 *
 * Snapshot the user buffer into a stack-local copy first to defeat
 * TOCTOU on the user side — once it's on our stack the kernel cannot
 * rewrite it underneath the comparison.  If the re-call returns -1 (the
 * original syscall succeeded but the re-call hit a transient failure),
 * give up rather than report a false divergence.  Sample one in a
 * hundred to stay in line with the rest of the oracle family.
 *
 * Note: a sibling trinity child issuing prlimit64(target_pid=us) is a
 * benign source of divergence — accept the false-positive rate
 * (1/100 sample × low background prlimit64 rate).
 */
static void post_getrlimit(struct syscallrecord *rec)
{
	struct rlimit local, syscall_buf;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a2 == 0)
		return;

	{
		void *rlim_p = (void *)(unsigned long) rec->a2;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a2. */
		if (looks_like_corrupted_ptr(rlim_p)) {
			outputerr("post_getrlimit: rejected suspicious rlim=%p (pid-scribbled?)\n",
				  rlim_p);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&syscall_buf, (struct rlimit *)(unsigned long) rec->a2,
	       sizeof(syscall_buf));

	memset(&local, 0, sizeof(local));
	if (getrlimit((unsigned int) rec->a1, &local) == -1)
		return;

	if (local.rlim_cur != syscall_buf.rlim_cur ||
	    local.rlim_max != syscall_buf.rlim_max) {
		output(0,
		       "getrlimit oracle: resource=%u syscall={cur=%lu,max=%lu} recheck={cur=%lu,max=%lu}\n",
		       (unsigned int) rec->a1,
		       (unsigned long) syscall_buf.rlim_cur,
		       (unsigned long) syscall_buf.rlim_max,
		       (unsigned long) local.rlim_cur,
		       (unsigned long) local.rlim_max);
		__atomic_add_fetch(&shm->stats.getrlimit_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getrlimit = {
	.name = "getrlimit",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "resource", [1] = "rlim" },
	.arg_params[0].list = ARGLIST(getrlimit_resources),
	.sanitise = sanitise_getrlimit,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.post = post_getrlimit,
};
