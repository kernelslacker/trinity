/*
 * SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, set,
	sigset_t __user *, oset, size_t, sigsetsize)
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
 * Snapshot of the four rt_sigprocmask input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the oracle at a foreign oset user
 * buffer, smear the sigsetsize length check, or steer the set != NULL
 * gate that decides whether to run the procfs cross-check at all.
 */
struct rt_sigprocmask_post_state {
	unsigned long how;
	unsigned long set;
	unsigned long oset;
	unsigned long sigsetsize;
};

static void sanitise_rt_sigprocmask(struct syscallrecord *rec)
{
	struct rt_sigprocmask_post_state *snap;

	rec->a4 = sizeof(sigset_t);

	/*
	 * oset (a3) is the kernel's writeback target for the previous mask
	 * (a4 bytes wide).  ARG_ADDRESS draws from the random pool, so a
	 * fuzzed pointer can land inside an alloc_shared region and let the
	 * kernel scribble bookkeeping.
	 */
	avoid_shared_buffer(&rec->a3, rec->a4);

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	/*
	 * Snapshot the four input args read by the post oracle.  Without
	 * this the post handler reads rec->a2/a3/a4 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original oset user buffer pointer, so the source
	 * memcpy would touch a foreign allocation that the guard never
	 * inspected, the sigsetsize gate would resolve against a scribbled
	 * value, and a stomped a2 (set) could flip the "skip when set !=
	 * NULL" gate either way -- letting the oracle race against a
	 * concurrent mutation, or silently suppressing a real comparison.
	 * post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->how        = rec->a1;
	snap->set        = rec->a2;
	snap->oset       = rec->a3;
	snap->sigsetsize = rec->a4;
	rec->post_state = (unsigned long) snap;
}

static unsigned long sigprocmask_how[] = {
	SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK,
};

/*
 * Oracle: when set (a2) is NULL, rt_sigprocmask() does not mutate any
 * mask — it just copies the calling thread's current blocked mask
 * (current->blocked, the per-thread sigset_t guarded by siglock) out to
 * oset.  The procfs view of the same fact is /proc/self/status, which
 * exposes current->blocked as "SigBlk:" via proc_pid_status() — also
 * under siglock, formatted via %016lx.  Both views read the same
 * sigset_t through different code paths, so a divergence between the
 * syscall's oset and SigBlk for the same task is its own corruption
 * shape: a torn write to current->blocked, a stale mask after a
 * sigaction race, or a copy_to_user that wrote past/before the live
 * mask.  Mirror of the rt_sigpending procfs oracle pattern.
 *
 * Skip when set != NULL: in that case the syscall mutated current->blocked
 * and oset (if any) holds the *previous* mask, not the live one — racing
 * that against /proc would give false positives.
 */
static void post_rt_sigprocmask(struct syscallrecord *rec)
{
	struct rt_sigprocmask_post_state *snap =
		(struct rt_sigprocmask_post_state *) rec->post_state;
	FILE *f;
	char line[128];
	uint64_t syscall_blocked, proc_blocked = 0;
	unsigned long sigblk = 0;
	bool have_sigblk = false;
	sigset_t buf;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_rt_sigprocmask: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;
	if (snap->set != 0)
		goto out_free;
	if (snap->oset == 0)
		goto out_free;
	if (snap->sigsetsize != sizeof(sigset_t))
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer field.  Reject
	 * a pid-scribbled oset before deref.
	 */
	if (looks_like_corrupted_ptr((void *) snap->oset)) {
		outputerr("post_rt_sigprocmask: rejected suspicious oset=%p (post_state-scribbled?)\n",
			  (void *) snap->oset);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		goto out_free;
	}

	memcpy(&buf, (const void *) snap->oset, sizeof(buf));
	memcpy(&syscall_blocked, &buf, sizeof(syscall_blocked));

	f = fopen("/proc/self/status", "r");
	if (!f)
		goto out_free;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "SigBlk:", 7) == 0) {
			if (sscanf(line + 7, "%lx", &sigblk) == 1)
				have_sigblk = true;
			break;
		}
	}
	fclose(f);

	if (!have_sigblk)
		goto out_free;

	proc_blocked = (uint64_t)sigblk;

	if (syscall_blocked != proc_blocked) {
		output(0, "rt_sigprocmask oracle: syscall=0x%016lx but "
		       "/proc/self/status SigBlk=0x%016lx\n",
		       (unsigned long)syscall_blocked,
		       (unsigned long)proc_blocked);
		__atomic_add_fetch(&shm->stats.rt_sigprocmask_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_rt_sigprocmask = {
	.name = "rt_sigprocmask",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.sanitise = sanitise_rt_sigprocmask,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN },
	.argname = { [0] = "how", [1] = "set", [2] = "oset", [3] = "sigsetsize" },
	.arg_params[0].list = ARGLIST(sigprocmask_how),
	.post = post_rt_sigprocmask,
};
