/*
 * SYSCALL_DEFINE0(getppid)
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
 * Oracle: getppid() returns the pid of this task's parent in the caller's
 * pid namespace.  The procfs view of the same fact is the "PPid:" line of
 * /proc/self/status, which proc_pid_status() derives from the task's
 * real_parent under the reader's pid_ns.  Both views walk the same
 * task_struct linkage but through different code paths — getppid() is a
 * thin syscall (sys_getppid -> task_tgid_vnr(rcu_dereference(real_parent))),
 * procfs goes via task_ppid_nr_ns() during the status seq_file fill — so a
 * divergence between the two for the same task is its own corruption shape:
 * stale rcu pointer, mismatched pid_ns translation, or a torn write to the
 * parent linkage.  Mirror of the getuid/getgid procfs oracles.
 */
static void post_getppid(struct syscallrecord *rec)
{
	FILE *f;
	char line[128];
	pid_t got, proc_ppid = (pid_t)-1;
	unsigned int ppid;

	long ret = (long) rec->retval;

	/*
	 * Kernel ABI: getppid() cannot fail; retval must be in
	 * [0, PID_MAX_LIMIT=4194304]. PPid==0 is legitimate (init has no
	 * parent in its own pid_ns), so the lower bound is 0, not 1.
	 */
	if (ret < 0 || ret > 4194304) {
		output(0, "getppid oracle: returned ppid %ld is out of range (must be in [0, PID_MAX_LIMIT=4194304], never -1)\n",
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
		if (strncmp(line, "PPid:", 5) == 0) {
			if (sscanf(line + 5, "%u", &ppid) == 1)
				proc_ppid = (pid_t)ppid;
			break;
		}
	}
	fclose(f);

	if (proc_ppid == (pid_t)-1)
		return;

	if (proc_ppid != got) {
		output(0, "getppid oracle: getppid()=%d but "
		       "/proc/self/status PPid=%d\n",
		       got, proc_ppid);
		__atomic_add_fetch(&shm->stats.getppid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getppid = {
	.name = "getppid",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.rettype = RET_PID_T,
	.post = post_getppid,
};
