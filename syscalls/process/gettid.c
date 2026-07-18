/*
 * SYSCALL_DEFINE0(gettid)
 */
#include <sys/types.h>
#include "proc-status.h"
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
	pid_t got, proc_pid;
	unsigned long pid_val;
	unsigned long retval = rec->retval;
	long ret = (long) retval;

	/* Kernel ABI: gettid() cannot fail; retval must be in [1, PID_MAX_LIMIT=4194304]. */
	if (ret < 1 || ret > 4194304) {
		output(0, "gettid oracle: returned pid %ld is out of range (must be in [1, PID_MAX_LIMIT=4194304], never -1)\n",
		       ret);
		return;
	}

	if (!ONE_IN(100))
		return;

	got = (pid_t) retval;

	if (!proc_status_read_uint_field("Pid", &pid_val))
		return;
	proc_pid = (pid_t)pid_val;

	if (proc_pid != got) {
		output(0, "gettid oracle: gettid()=%d but "
		       "/proc/self/status Pid=%d\n",
		       got, proc_pid);
		__atomic_add_fetch(&shm->stats.oracle.gettid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_gettid = {
	.name = "gettid",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.rettype = RET_PID_T,
	.ret_objtype = OBJ_PID,
	.post = post_gettid,
};
