/*
 * SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "compat.h"
#include "utils.h"

#if defined(SYS_getrlimit) || defined(__NR_getrlimit)
#ifndef SYS_getrlimit
#define SYS_getrlimit __NR_getrlimit
#endif
#define HAVE_SYS_GETRLIMIT 1
#endif

#ifdef HAVE_SYS_GETRLIMIT
/*
 * Snapshot of the two getrlimit input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the recheck at a different RLIMIT_*
 * resource or redirect the source memcpy at a foreign user buffer.
 */
struct getrlimit_post_state {
	unsigned int resource;
	void *rlim;
};
#endif

static unsigned long getrlimit_resources[] = {
	RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA,
	RLIMIT_FSIZE, RLIMIT_LOCKS, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE,
	RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS,
	RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK,
};

static void sanitise_getrlimit(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_GETRLIMIT
	struct getrlimit_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a2, sizeof(struct rlimit));

#ifdef HAVE_SYS_GETRLIMIT
	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original rlim
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation, and a stomped resource slot retargets the recheck at
	 * a wholly different RLIMIT_* than the first call ran against.
	 * post_state is private to the post handler.  Gated on
	 * HAVE_SYS_GETRLIMIT to mirror the .post registration -- on systems
	 * without SYS_getrlimit the post handler is not registered and a
	 * snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->resource = (unsigned int) rec->a1;
	snap->rlim     = (void *)(unsigned long) rec->a2;
	rec->post_state = (unsigned long) snap;
#endif
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
 * TOCTOU defeat: the two input args (resource, rlim) are snapshotted at
 * sanitise time into a heap struct in rec->post_state, so a sibling that
 * scribbles rec->aN between syscall return and post entry cannot retarget
 * the recheck at a different RLIMIT_* (the resource scalar) or redirect
 * the source memcpy at a foreign user buffer (the rlim pointer).  The
 * user buffer payload is then snapshotted into a stack-local before the
 * re-call writes into a fresh private stack buffer -- a sibling could
 * mutate the user buffer itself mid-syscall and forge a clean compare.
 *
 * If the re-call returns -1 (the original syscall succeeded but the
 * re-call hit a transient failure), give up rather than report a false
 * divergence.  Sample one in a hundred to stay in line with the rest of
 * the oracle family.
 *
 * Note: a sibling trinity child issuing prlimit64(target_pid=us) is a
 * benign source of divergence -- accept the false-positive rate
 * (1/100 sample x low background prlimit64 rate).
 */
#ifdef HAVE_SYS_GETRLIMIT
static void post_getrlimit(struct syscallrecord *rec)
{
	struct getrlimit_post_state *snap =
		(struct getrlimit_post_state *) rec->post_state;
	struct rlimit local, syscall_buf;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getrlimit: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->rlim == NULL)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner rlim pointer field.
	 * Reject pid-scribbled rlim before deref.
	 */
	if (looks_like_corrupted_ptr(rec, snap->rlim)) {
		outputerr("post_getrlimit: rejected suspicious rlim=%p (post_state-scribbled?)\n",
			  snap->rlim);
		goto out_free;
	}

	memcpy(&syscall_buf, (struct rlimit *) snap->rlim, sizeof(syscall_buf));

	memset(&local, 0, sizeof(local));
	if (getrlimit(snap->resource, &local) == -1)
		goto out_free;

	if (local.rlim_cur != syscall_buf.rlim_cur ||
	    local.rlim_max != syscall_buf.rlim_max) {
		output(0,
		       "getrlimit oracle: resource=%u syscall={cur=%lu,max=%lu} recheck={cur=%lu,max=%lu}\n",
		       snap->resource,
		       (unsigned long) syscall_buf.rlim_cur,
		       (unsigned long) syscall_buf.rlim_max,
		       (unsigned long) local.rlim_cur,
		       (unsigned long) local.rlim_max);
		__atomic_add_fetch(&shm->stats.getrlimit_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif

struct syscallentry syscall_getrlimit = {
	.name = "getrlimit",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "resource", [1] = "rlim" },
	.arg_params[0].list = ARGLIST(getrlimit_resources),
	.sanitise = sanitise_getrlimit,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
#ifdef HAVE_SYS_GETRLIMIT
	.post = post_getrlimit,
#endif
};
