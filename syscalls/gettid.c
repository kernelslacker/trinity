/*
 * SYSCALL_DEFINE0(gettid)
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: gettid() returns the calling task's tid in the caller's pid
 * namespace.  The procfs view of the same fact is the "Pid:" line of
 * /proc/self/status, which proc_pid_status() derives via task_pid_nr_ns()
 * under the reader's pid_ns.  Both views walk the same task_struct pid
 * linkage but through different code paths — sys_gettid is a thin
 * __task_pid_nr_ns(current, PIDTYPE_PID, NULL) call, procfs goes via the
 * status seq_file fill — so a divergence between the two for the same task
 * is its own corruption shape: torn write to the pid linkage, mismatched
 * pid_ns translation, or a stale rcu pointer.  Mirror of the getpid Tgid
 * oracle, applied to the per-task pid side.
 */
static void post_gettid(struct syscallrecord *rec)
{
	FILE *f;
	char line[128];
	pid_t got, proc_pid = (pid_t)-1;
	unsigned int pid_int;

	long ret = (long) rec->retval;

	/* Kernel ABI: gettid() cannot fail; retval must be in [1, PID_MAX_LIMIT=4194304]. */
	if (ret < 1 || ret > 4194304) {
		output(0, "gettid oracle: returned pid %ld is out of range (must be in [1, PID_MAX_LIMIT=4194304], never -1)\n",
		       ret);
		return;
	}

	if (!ONE_IN(100))
		return;

	got = (pid_t) rec->retval;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Pid:", 4) == 0) {
			if (sscanf(line + 4, "%u", &pid_int) == 1)
				proc_pid = (pid_t)pid_int;
			break;
		}
	}
	fclose(f);

	if (proc_pid == (pid_t)-1)
		return;

	if (proc_pid != got) {
		output(0, "gettid oracle: gettid()=%d but "
		       "/proc/self/status Pid=%d\n",
		       got, proc_pid);
		__atomic_add_fetch(&shm->stats.gettid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_gettid = {
	.name = "gettid",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.rettype = RET_PID_T,
	.post = post_gettid,
};
