/*
 * SYSCALL_DEFINE0(getpid)
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
 * Oracle: getpid() returns this task's thread group id in the caller's
 * pid namespace.  The procfs view of the same fact is the "Tgid:" line of
 * /proc/self/status, which proc_pid_status() derives via task_tgid_nr_ns()
 * under the reader's pid_ns.  Both views walk the same task_struct thread
 * group linkage but through different code paths — sys_getpid is a thin
 * task_tgid_vnr(current) call, procfs goes via task_tgid_nr_ns() during the
 * status seq_file fill — so a divergence between the two for the same task
 * is its own corruption shape: torn write to thread-group linkage,
 * mismatched pid_ns translation, or a stale rcu pointer.  Mirror of the
 * getppid procfs oracle.
 */
static void post_getpid(struct syscallrecord *rec)
{
	FILE *f;
	char line[128];
	pid_t got, proc_tgid = (pid_t)-1;
	unsigned int tgid;

	if (!ONE_IN(100))
		return;

	got = (pid_t) rec->retval;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Tgid:", 5) == 0) {
			if (sscanf(line + 5, "%u", &tgid) == 1)
				proc_tgid = (pid_t)tgid;
			break;
		}
	}
	fclose(f);

	if (proc_tgid == (pid_t)-1)
		return;

	if (proc_tgid != got) {
		output(0, "getpid oracle: getpid()=%d but "
		       "/proc/self/status Tgid=%d\n",
		       got, proc_tgid);
		__atomic_add_fetch(&shm->stats.getpid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getpid = {
	.name = "getpid",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.rettype = RET_PID_T,
	.post = post_getpid,
};
