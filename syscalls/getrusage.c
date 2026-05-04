/*
 * SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru)
 */
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long getrusage_who[] = {
	RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD,
};

#if defined(SYS_getrusage) || defined(__NR_getrusage)
/*
 * Snapshot of the two getrusage input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot flip the who selector to a different accounting
 * domain (RUSAGE_SELF vs RUSAGE_THREAD vs RUSAGE_CHILDREN diverge wildly)
 * or redirect the source memcpy at a foreign user buffer.
 */
struct getrusage_post_state {
	unsigned long who;
	unsigned long ru;
};
#endif

static void sanitise_getrusage(struct syscallrecord *rec)
{
#if defined(SYS_getrusage) || defined(__NR_getrusage)
	struct getrusage_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	avoid_shared_buffer(&rec->a2, sizeof(struct rusage));

#if defined(SYS_getrusage) || defined(__NR_getrusage)
	/*
	 * Snapshot the two input args for the post oracle.  Without this
	 * the post handler reads rec->aN at post-time, when a sibling
	 * syscall may have scribbled the slots: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original ru
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation, and a stomped who slot retargets the re-issue at a
	 * different accounting domain than the first call ran in.
	 * post_state is private to the post handler.  Gated on the syscall
	 * number macro to mirror the .post registration -- on systems
	 * without SYS_getrusage the post handler's re-issue would not work
	 * and a snapshot only the post handler can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->who       = rec->a1;
	snap->ru        = rec->a2;
	rec->post_state = (unsigned long) snap;
#endif
}

/*
 * Oracle: getrusage(who, &ru) reports a struct rusage describing the
 * calling task's resource accounting -- a mix of CPU-time pairs
 * (ru_utime / ru_stime), monotonic event counters (ru_minflt, ru_majflt,
 * ru_inblock, ru_oublock, ru_nvcsw, ru_nivcsw, ru_nsignals), the
 * high-water-mark gauge ru_maxrss, and a block of fields that Linux has
 * hardcoded to zero since the dawn of the syscall (ru_ixrss, ru_idrss,
 * ru_isrss, ru_msgsnd, ru_msgrcv).  Which slice of accounting the
 * kernel tallies depends on who: RUSAGE_SELF totals the live process,
 * RUSAGE_THREAD this thread alone, RUSAGE_CHILDREN only the
 * already-reaped children -- but every reported field is either
 * non-decreasing under the same who or pinned at zero by ABI.  Re-
 * issuing for the same who a moment later must therefore see every
 * monotonic field at least as large as the first read and every
 * deprecated field still at zero.  A field that goes backwards or a
 * deprecated slot that suddenly carries a non-zero value is not benign
 * drift -- the kernel has no path that legitimately rewinds these
 * counters or wakes the deprecated lanes -- it points at one of:
 *
 *   - copy_to_user mis-write: the kernel produced the right values but
 *     they landed in the wrong slot in the user buffer or arrived torn.
 *   - 32-bit-on-64-bit compat sign-extension on the long counters: a
 *     small positive ru_minflt sign-extending to a huge negative value
 *     compares as decreasing on the next read.
 *   - struct-layout mismatch shifting adjacent fields, e.g. ru_maxrss
 *     landing in the ru_utime slot so a subsequent read with the right
 *     layout shows a smaller utime where a larger maxrss used to sit.
 *   - sibling-thread scribble of the user receive buffer between the
 *     syscall return and our post-hook re-read.
 *
 * TOCTOU defeat (two arguments worth of it): the who selector sits in
 * rec->a1 and a sibling thread in the same trinity child can scribble
 * either rec->a1 or the rec->a2 user-buffer payload between the
 * original syscall return and our re-issue.  Re-calling with whatever
 * rec->a1 happens to hold by then resolves a different accounting
 * domain (RUSAGE_THREAD vs RUSAGE_CHILDREN are wildly different
 * numerically) and produces a false divergence; comparing against a
 * scribbled rec->a2 payload does the same.  The two input args are
 * snapshotted at sanitise time into a heap struct in rec->post_state, so
 * the post handler reads who and the ru pointer from the snapshot rather
 * than from rec->aN.  The user-buffer payload at *ru is then copied into
 * a stack-local before the re-call, with a private stack buffer for the
 * recall result so a sibling cannot mutate it mid-syscall and forge a
 * clean compare.  If the re-call fails (a sibling thread raced
 * credentials or otherwise broke the second call) give up rather than
 * report.
 *
 * Comparison rules:
 *   - ru_utime / ru_stime are timeval pairs that the kernel updates
 *     monotonically but which advance even within the post-hook itself
 *     (the hook burns CPU time on the same task), so equality is too
 *     strict; treat (tv_sec, tv_usec) as a single ordered pair where
 *     tv_sec dominates and only flag a strict decrease.
 *   - ru_maxrss, ru_minflt, ru_majflt, ru_inblock, ru_oublock, ru_nvcsw,
 *     ru_nivcsw, ru_nsignals are long counters the kernel only
 *     increments; flag if recall < first.
 *   - ru_ixrss, ru_idrss, ru_isrss, ru_msgsnd, ru_msgrcv are deprecated
 *     to permanently zero on Linux.  A regression that flips one to
 *     non-zero would silently break userspace assumptions baked in for
 *     decades; flag if either snapshot is non-zero or they differ.
 *
 * Compare every field with no early-return so multi-field corruption
 * surfaces in a single sample, but bump the anomaly counter only once
 * per sample.  Emit one log line carrying the who arg plus both
 * snapshots' relevant fields so the operator sees the full divergence
 * shape at once.  Sample one in a hundred to stay in line with the
 * rest of the oracle family.  Wired only on syscall_getrusage -- the
 * syscall stands alone with no aliases.
 */
static void post_getrusage(struct syscallrecord *rec)
{
#if defined(SYS_getrusage) || defined(__NR_getrusage)
	struct getrusage_post_state *snap =
		(struct getrusage_post_state *) rec->post_state;
	int who;
	struct rusage first, recall;
	int utime_dec, stime_dec;
	int diverged = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_getrusage: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if ((long) rec->retval != 0)
		goto out_free;

	if (snap->ru == 0)
		goto out_free;

	who = (int) snap->who;

	{
		void *ru = (void *)(unsigned long) snap->ru;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner ru
		 * pointer field.  Reject pid-scribbled ru before deref.
		 */
		if (looks_like_corrupted_ptr(ru)) {
			outputerr("post_getrusage: rejected suspicious ru=%p (post_state-scribbled?)\n",
				  ru);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	memcpy(&first, (struct rusage *)(unsigned long) snap->ru,
	       sizeof(first));

	if (getrusage(who, &recall) != 0)
		goto out_free;

	utime_dec = (recall.ru_utime.tv_sec < first.ru_utime.tv_sec) ||
		    (recall.ru_utime.tv_sec == first.ru_utime.tv_sec &&
		     recall.ru_utime.tv_usec < first.ru_utime.tv_usec);
	stime_dec = (recall.ru_stime.tv_sec < first.ru_stime.tv_sec) ||
		    (recall.ru_stime.tv_sec == first.ru_stime.tv_sec &&
		     recall.ru_stime.tv_usec < first.ru_stime.tv_usec);

	if (utime_dec ||
	    stime_dec ||
	    recall.ru_maxrss   < first.ru_maxrss   ||
	    recall.ru_minflt   < first.ru_minflt   ||
	    recall.ru_majflt   < first.ru_majflt   ||
	    recall.ru_inblock  < first.ru_inblock  ||
	    recall.ru_oublock  < first.ru_oublock  ||
	    recall.ru_nvcsw    < first.ru_nvcsw    ||
	    recall.ru_nivcsw   < first.ru_nivcsw   ||
	    recall.ru_nsignals < first.ru_nsignals ||
	    first.ru_ixrss  != 0 || recall.ru_ixrss  != 0 ||
	    first.ru_idrss  != 0 || recall.ru_idrss  != 0 ||
	    first.ru_isrss  != 0 || recall.ru_isrss  != 0 ||
	    first.ru_msgsnd != 0 || recall.ru_msgsnd != 0 ||
	    first.ru_msgrcv != 0 || recall.ru_msgrcv != 0)
		diverged = 1;

	if (diverged) {
		output(0,
		       "[oracle:getrusage] who %d utime %ld.%06ld vs %ld.%06ld stime %ld.%06ld vs %ld.%06ld maxrss %ld vs %ld minflt %ld vs %ld majflt %ld vs %ld inblock %ld vs %ld oublock %ld vs %ld nvcsw %ld vs %ld nivcsw %ld vs %ld nsignals %ld vs %ld ixrss %ld vs %ld idrss %ld vs %ld isrss %ld vs %ld msgsnd %ld vs %ld msgrcv %ld vs %ld\n",
		       who,
		       (long) first.ru_utime.tv_sec,  (long) first.ru_utime.tv_usec,
		       (long) recall.ru_utime.tv_sec, (long) recall.ru_utime.tv_usec,
		       (long) first.ru_stime.tv_sec,  (long) first.ru_stime.tv_usec,
		       (long) recall.ru_stime.tv_sec, (long) recall.ru_stime.tv_usec,
		       first.ru_maxrss,   recall.ru_maxrss,
		       first.ru_minflt,   recall.ru_minflt,
		       first.ru_majflt,   recall.ru_majflt,
		       first.ru_inblock,  recall.ru_inblock,
		       first.ru_oublock,  recall.ru_oublock,
		       first.ru_nvcsw,    recall.ru_nvcsw,
		       first.ru_nivcsw,   recall.ru_nivcsw,
		       first.ru_nsignals, recall.ru_nsignals,
		       first.ru_ixrss,    recall.ru_ixrss,
		       first.ru_idrss,    recall.ru_idrss,
		       first.ru_isrss,    recall.ru_isrss,
		       first.ru_msgsnd,   recall.ru_msgsnd,
		       first.ru_msgrcv,   recall.ru_msgrcv);
		__atomic_add_fetch(&shm->stats.getrusage_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
#else
	(void) rec;
#endif
}

struct syscallentry syscall_getrusage = {
	.name = "getrusage",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "who", [1] = "ru" },
	.arg_params[0].list = ARGLIST(getrusage_who),
	.sanitise = sanitise_getrusage,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.post = post_getrusage,
};
