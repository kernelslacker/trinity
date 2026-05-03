/*
 * SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, set)
 */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_sigpending(struct syscallrecord *rec)
{
	/*
	 * Legacy sigpending takes a single old_sigset_t (one word) writeback
	 * target.  rt_sigpending was scrubbed in the prior batch using its
	 * caller-supplied a2 length; sigpending has no length arg, so use
	 * sigset_t as the conservative upper bound.
	 */
	avoid_shared_buffer(&rec->a1, sizeof(sigset_t));
}

#if defined(SYS_sigpending) || defined(__NR_sigpending)
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
	FILE *f;
	char line[128];
	char raw[128] = "";
	unsigned long user_snap;	/* old_sigset_t == unsigned long on x86_64 */
	uint64_t syscall_pending, proc_pending;
	unsigned long sigpnd = 0;
	bool have_sigpnd = false;

	if (!ONE_IN(100))
		return;

	if (rec->retval != 0)
		return;
	if (rec->a1 == 0)
		return;

	{
		void *set = (void *)(unsigned long) rec->a1;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1. */
		if (looks_like_corrupted_ptr(set)) {
			outputerr("post_sigpending: rejected suspicious set=%p (pid-scribbled?)\n",
				  set);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	/*
	 * Snapshot the user buffer BEFORE the proc read so a sibling-thread
	 * scribble of the buffer between syscall return and our procfs read
	 * can't alias the comparison.
	 */
	memcpy(&user_snap, (const void *)(unsigned long)rec->a1, sizeof(user_snap));
	syscall_pending = (uint64_t)user_snap;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
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
		return;

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
}
#endif

struct syscallentry syscall_sigpending = {
	.name = "sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "set" },
	.sanitise = sanitise_sigpending,
#if defined(SYS_sigpending) || defined(__NR_sigpending)
	.post = post_sigpending,
#endif
};
