/*
 * SYSCALL_DEFINE0(getpgrp)
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
 * Oracle: getpgrp() returns the process group id of the current task in
 * the caller's pid namespace — i.e. the same kernel field as getpgid(0),
 * just without the pid argument.  The procfs view of the same fact is
 * the "NSpgid:" line of /proc/self/status, which proc_pid_status()
 * derives via pid_nr_ns() walking the task's pgrp pid for each ancestor
 * pid_ns.  Both views walk the same task_struct -> signal ->
 * __pids[PIDTYPE_PGID] linkage, but sys_getpgrp goes through
 * task_pgrp_vnr(current) while procfs builds the namespace list — so a
 * divergence between the two for the same task is its own corruption
 * shape: torn write to the pgrp pid linkage, mismatched pid_ns
 * translation, or a stale rcu pointer.
 *
 * NSpgid is a tab-separated list of pids, one per pid_ns from outermost
 * to innermost; the LAST integer is the caller's view, which is what
 * sys_getpgrp returns.  On a single-namespace host there's only one int
 * and the same parse handles it.
 */
static void post_getpgrp(struct syscallrecord *rec)
{
	FILE *f;
	char line[256];
	pid_t got, proc_pgid = (pid_t)-1;

	long ret = (long) rec->retval;

	/* Kernel ABI: getpgrp() cannot fail; retval must be in [1, PID_MAX_LIMIT=4194304]. */
	if (ret < 1 || ret > 4194304) {
		output(0, "getpgrp oracle: returned pgid %ld is out of range (must be in [1, PID_MAX_LIMIT=4194304], never -1)\n",
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
		if (strncmp(line, "NSpgid:", 7) == 0) {
			char *p = line + 7;
			char *tok, *saveptr = NULL;
			unsigned int last = 0;
			int found = 0;

			for (tok = strtok_r(p, " \t\n", &saveptr); tok;
			     tok = strtok_r(NULL, " \t\n", &saveptr)) {
				if (sscanf(tok, "%u", &last) == 1)
					found = 1;
			}
			if (found)
				proc_pgid = (pid_t)last;
			break;
		}
	}
	fclose(f);

	if (proc_pgid == (pid_t)-1)
		return;

	if (proc_pgid != got) {
		output(0, "getpgrp oracle: getpgrp()=%d but "
		       "/proc/self/status NSpgid=%d\n",
		       got, proc_pgid);
		__atomic_add_fetch(&shm->stats.getpgrp_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getpgrp = {
	.name = "getpgrp",
	.num_args = 0,
	.rettype = RET_PID_T,
	.group = GROUP_PROCESS,
	.post = post_getpgrp,
};
