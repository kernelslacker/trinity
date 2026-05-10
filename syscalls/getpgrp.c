/*
 * SYSCALL_DEFINE0(getpgrp)
 */
#include <fcntl.h>
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
	char buf[2048];
	char *line, *eol;
	ssize_t n;
	int fd;
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

	/* Raw open/read instead of fopen/fgets/fclose: this post handler runs
	 * thousands of times per second under fuzz, and stdio's per-call malloc
	 * of FILE struct + IO buffer is heap traffic we don't need. */
	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	/* Anchor on a newline so an "NSpgid:" substring inside an earlier
	 * field cannot mis-target the parse. */
	line = strstr(buf, "\nNSpgid:");
	if (line != NULL) {
		char *p = line + 8;
		char *tok, *saveptr = NULL;
		unsigned int last = 0;
		int found = 0;

		/* Bound strtok_r to this single line by NUL-terminating at the
		 * next newline; the original fgets-based code only saw one line
		 * at a time. */
		eol = strchr(p, '\n');
		if (eol != NULL)
			*eol = '\0';

		for (tok = strtok_r(p, " \t", &saveptr); tok;
		     tok = strtok_r(NULL, " \t", &saveptr)) {
			if (sscanf(tok, "%u", &last) == 1)
				found = 1;
		}
		if (found)
			proc_pgid = (pid_t)last;
	}

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
