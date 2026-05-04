/*
 * SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, set)
 */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#if defined(SYS_sigpending) || defined(__NR_sigpending)
#ifndef SYS_sigpending
#define SYS_sigpending __NR_sigpending
#endif
#define HAVE_SYS_SIGPENDING 1
#endif

#ifdef HAVE_SYS_SIGPENDING
/*
 * Snapshot of the sigpending input arg read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->a1 between the syscall returning and the post
 * handler running cannot redirect the oracle at a foreign set user
 * buffer.
 */
struct sigpending_post_state {
	unsigned long set;
};
#endif

static void sanitise_sigpending(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_SIGPENDING
	struct sigpending_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;
#endif

	/*
	 * Legacy sigpending takes a single old_sigset_t (one word) writeback
	 * target.  rt_sigpending was scrubbed in the prior batch using its
	 * caller-supplied a2 length; sigpending has no length arg, so use
	 * sigset_t as the conservative upper bound.
	 */
	avoid_shared_buffer(&rec->a1, sizeof(sigset_t));

#ifdef HAVE_SYS_SIGPENDING
	/*
	 * Snapshot the input arg read by the post oracle.  Without this the
	 * post handler reads rec->a1 at post-time, when a sibling syscall
	 * may have scribbled the slot: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original set user
	 * buffer pointer, so the source memcpy would touch a foreign
	 * allocation that the guard never inspected.  post_state is private
	 * to the post handler.  Gated on HAVE_SYS_SIGPENDING to mirror the
	 * .post registration -- on systems without SYS_sigpending the post
	 * handler is not registered and a snapshot only the post handler
	 * can free would leak.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->set = rec->a1;
	rec->post_state = (unsigned long) snap;
#endif
}

#ifdef HAVE_SYS_SIGPENDING
/*
 * Oracle: sigpending(2) writes the calling thread's pending-signal mask
 * to a single old_sigset_t (== unsigned long on x86_64).  The procfs
 * view of the same fact is /proc/self/status "SigPnd:", which formats
 * the per-thread pending mask via render_sigset_t() after a separate
 * siglock acquire.  Both views read task->pending.signal but through
 * entirely separate paths — siglock-guarded copy_to_user vs
 * proc_pid_status() rendering — so a divergence between them for the
 * same task is its own corruption shape: a torn write into the user
 * buffer, a stale signal_struct rcu pointer, or a copy_to_user that
 * overwrote past/before the live mask.  Mirror of the rt_sigpending
 * procfs oracle pattern; the only difference is the writeback width
 * (old_sigset_t vs sigset_t).
 *
 * False-positive sources at ONE_IN(100):
 *   - A sibling thread receiving and queueing a signal between syscall
 *     return and our procfs read will legitimately advance SigPnd.
 *     Acceptable at this sample rate.
 *   - SigPnd in /proc/self/status reports per-thread pending signals;
 *     sigpending(2) returns per-thread signals on Linux >= 2.6.  These
 *     are the same view by construction — a documented match.
 *
 * Wrapped in #if defined(SYS_sigpending) || defined(__NR_sigpending)
 * so toolchains lacking the legacy define still build the entry; the
 * syscall is x86_64 slot 127 and present on all current targets, but
 * minimal libcs may omit the macro.
 */
static void post_sigpending(struct syscallrecord *rec)
{
	struct sigpending_post_state *snap =
		(struct sigpending_post_state *) rec->post_state;
	FILE *f;
	char line[128];
	char raw[128] = "";
	unsigned long user_snap;	/* old_sigset_t == unsigned long on x86_64 */
	uint64_t syscall_pending, proc_pending;
	unsigned long sigpnd = 0;
	bool have_sigpnd = false;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_sigpending: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;
	if (snap->set == 0)
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer field.  Reject
	 * a pid-scribbled set before deref.
	 */
	if (looks_like_corrupted_ptr((void *) snap->set)) {
		outputerr("post_sigpending: rejected suspicious set=%p (post_state-scribbled?)\n",
			  (void *) snap->set);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		goto out_free;
	}

	/*
	 * Snapshot the user buffer BEFORE the proc read so a sibling-thread
	 * scribble of the buffer between syscall return and our procfs read
	 * can't alias the comparison.
	 */
	memcpy(&user_snap, (const void *) snap->set, sizeof(user_snap));
	syscall_pending = (uint64_t)user_snap;

	f = fopen("/proc/self/status", "r");
	if (!f)
		goto out_free;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "SigPnd:", 7) == 0) {
			strncpy(raw, line, sizeof(raw) - 1);
			raw[sizeof(raw) - 1] = '\0';
			if (sscanf(line + 7, "%lx", &sigpnd) == 1)
				have_sigpnd = true;
			break;
		}
	}
	fclose(f);

	if (!have_sigpnd)
		goto out_free;

	proc_pending = (uint64_t)sigpnd;

	if (syscall_pending != proc_pending) {
		size_t rl = strlen(raw);
		if (rl && raw[rl - 1] == '\n')
			raw[rl - 1] = '\0';
		output(0, "sigpending oracle: syscall=0x%016lx but "
		       "/proc/self/status SigPnd=0x%016lx (raw=\"%s\")\n",
		       (unsigned long)syscall_pending,
		       (unsigned long)proc_pending,
		       raw);
		__atomic_add_fetch(&shm->stats.sigpending_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}
#endif

struct syscallentry syscall_sigpending = {
	.name = "sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "set" },
	.sanitise = sanitise_sigpending,
#ifdef HAVE_SYS_SIGPENDING
	.post = post_sigpending,
#endif
};
