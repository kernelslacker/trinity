/*
 * SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, set, size_t, sigsetsize)
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

static void sanitise_rt_sigpending(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, rec->a2);
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
	FILE *f;
	char line[128];
	uint64_t syscall_pending, proc_pending = 0;
	unsigned long sigpnd = 0, shdpnd = 0;
	bool have_sigpnd = false, have_shdpnd = false;
	sigset_t buf;

	if (!ONE_IN(100))
		return;

	if (rec->retval != 0)
		return;
	if (rec->a1 == 0)
		return;
	if (rec->a2 != sizeof(sigset_t))
		return;

	memcpy(&buf, (void *)(unsigned long)rec->a1, sizeof(buf));
	memcpy(&syscall_pending, &buf, sizeof(syscall_pending));

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
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
		return;

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
