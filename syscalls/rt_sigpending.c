/*
 * SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, set, size_t, sigsetsize)
 */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two rt_sigpending input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the oracle at a foreign set user
 * buffer or alias the sigsetsize length check.
 */
struct rt_sigpending_post_state {
	unsigned long set;
	unsigned long sigsetsize;
};

static void sanitise_rt_sigpending(struct syscallrecord *rec)
{
	struct rt_sigpending_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a1, rec->a2);

	/*
	 * Snapshot the two input args read by the post oracle.  Without
	 * this the post handler reads rec->a1/a2 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original set user buffer pointer, so the source
	 * memcpy would touch a foreign allocation that the guard never
	 * inspected, and the sigsetsize gate would resolve against a
	 * scribbled value.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->set        = rec->a1;
	snap->sigsetsize = rec->a2;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: rt_sigpending() copies the union of the calling thread's
 * per-thread pending mask and the per-process shared pending mask out
 * to userspace.  The procfs view of the same fact is /proc/self/status,
 * which exposes the two halves separately as "SigPnd:" (per-thread,
 * task->pending.signal) and "ShdPnd:" (shared, task->signal->shared_pending.signal).
 * Both views read the same sigpending bitmaps but through different code
 * paths — the syscall takes siglock once and copies sigorsets(thread,
 * shared), procfs walks proc_pid_status() which formats each half via
 * %016lx after taking siglock per render — so a divergence between the
 * syscall's union and (SigPnd | ShdPnd) for the same task is its own
 * corruption shape: a torn write to signal->shared_pending, a stale rcu
 * pointer to the signal_struct, or a sigset_t copy_to_user that wrote
 * past/before the live mask.  Mirror of the getppid procfs oracle pattern.
 */
static void post_rt_sigpending(struct syscallrecord *rec)
{
	struct rt_sigpending_post_state *snap =
		(struct rt_sigpending_post_state *) rec->post_state;
	FILE *f;
	char line[128];
	uint64_t syscall_pending, proc_pending = 0;
	unsigned long sigpnd = 0, shdpnd = 0;
	bool have_sigpnd = false, have_shdpnd = false;
	sigset_t buf;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_rt_sigpending: rejected suspicious post_state=%p (pid-scribbled?)\n",
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
	if (snap->sigsetsize != sizeof(sigset_t))
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer field.  Reject
	 * a pid-scribbled set before deref.
	 */
	if (looks_like_corrupted_ptr((void *) snap->set)) {
		outputerr("post_rt_sigpending: rejected suspicious set=%p (post_state-scribbled?)\n",
			  (void *) snap->set);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		goto out_free;
	}

	memcpy(&buf, (const void *) snap->set, sizeof(buf));
	memcpy(&syscall_pending, &buf, sizeof(syscall_pending));

	f = fopen("/proc/self/status", "r");
	if (!f)
		goto out_free;
	while (fgets(line, sizeof(line), f)) {
		if (!have_sigpnd && strncmp(line, "SigPnd:", 7) == 0) {
			if (sscanf(line + 7, "%lx", &sigpnd) == 1)
				have_sigpnd = true;
		} else if (!have_shdpnd && strncmp(line, "ShdPnd:", 7) == 0) {
			if (sscanf(line + 7, "%lx", &shdpnd) == 1)
				have_shdpnd = true;
		}
		if (have_sigpnd && have_shdpnd)
			break;
	}
	fclose(f);

	if (!have_sigpnd || !have_shdpnd)
		goto out_free;

	proc_pending = (uint64_t)sigpnd | (uint64_t)shdpnd;

	if (syscall_pending != proc_pending) {
		output(0, "rt_sigpending oracle: syscall=0x%016lx but "
		       "/proc/self/status SigPnd|ShdPnd=0x%016lx "
		       "(SigPnd=0x%016lx ShdPnd=0x%016lx)\n",
		       (unsigned long)syscall_pending,
		       (unsigned long)proc_pending,
		       sigpnd, shdpnd);
		__atomic_add_fetch(&shm->stats.rt_sigpending_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_rt_sigpending = {
	.name = "rt_sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "set", [1] = "sigsetsize" },
	.sanitise = sanitise_rt_sigpending,
	.post = post_rt_sigpending,
};
