/*
 * SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, set,
	sigset_t __user *, oset, size_t, sigsetsize)
 */
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_rt_sigprocmask(struct syscallrecord *rec)
{
	rec->a4 = sizeof(sigset_t);

	/*
	 * oset (a3) is the kernel's writeback target for the previous mask
	 * (a4 bytes wide).  ARG_ADDRESS draws from the random pool, so a
	 * fuzzed pointer can land inside an alloc_shared region and let the
	 * kernel scribble bookkeeping.
	 */
	avoid_shared_buffer(&rec->a3, rec->a4);
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
	FILE *f;
	char line[128];
	uint64_t syscall_blocked, proc_blocked = 0;
	unsigned long sigblk = 0;
	bool have_sigblk = false;
	sigset_t buf;

	if (!ONE_IN(100))
		return;

	if (rec->retval != 0)
		return;
	if (rec->a2 != 0)
		return;
	if (rec->a3 == 0)
		return;
	if (rec->a4 != sizeof(sigset_t))
		return;

	{
		void *oset = (void *)(unsigned long) rec->a3;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a3. */
		if (looks_like_corrupted_ptr(oset)) {
			outputerr("post_rt_sigprocmask: rejected suspicious oset=%p (pid-scribbled?)\n",
				  oset);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&buf, (void *)(unsigned long)rec->a3, sizeof(buf));
	memcpy(&syscall_blocked, &buf, sizeof(syscall_blocked));

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "SigBlk:", 7) == 0) {
			if (sscanf(line + 7, "%lx", &sigblk) == 1)
				have_sigblk = true;
			break;
		}
	}
	fclose(f);

	if (!have_sigblk)
		return;

	proc_blocked = (uint64_t)sigblk;

	if (syscall_blocked != proc_blocked) {
		output(0, "rt_sigprocmask oracle: syscall=0x%016lx but "
		       "/proc/self/status SigBlk=0x%016lx\n",
		       (unsigned long)syscall_blocked,
		       (unsigned long)proc_blocked);
		__atomic_add_fetch(&shm->stats.rt_sigprocmask_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
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
