/*
 * SYSCALL_DEFINE1(getpgid, pid_t, pid)
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
#include "utils.h"

/*
 * Oracle: getpgid(0) returns the process group id of the current task in
 * the caller's pid namespace.  The procfs view of the same fact is the
 * "NSpgid:" line of /proc/self/status, which proc_pid_status() derives via
 * pid_nr_ns() walking the task's pgrp pid for each ancestor pid_ns.  Both
 * views walk the same task_struct -> signal -> __pids[PIDTYPE_PGID]
 * linkage, but sys_getpgid goes through task_pgrp_vnr(p) while procfs
 * builds the namespace list — so a divergence between the two for the
 * same task is its own corruption shape: torn write to the pgrp pid
 * linkage, mismatched pid_ns translation, or a stale rcu pointer.
 *
 * Only meaningful for getpgid(0) — querying another process's pgid would
 * race procfs against an unrelated task.
 *
 * NSpgid is a tab-separated list of pids, one per pid_ns from outermost
 * to innermost; the LAST integer is the caller's view, which is what
 * sys_getpgid returns.  On a single-namespace host there's only one int
 * and the same parse handles it.
 */
static void post_getpgid(struct syscallrecord *rec)
{
	char buf[2048];
	char *line, *eol;
	ssize_t n;
	int fd;
	pid_t got, proc_pgid = (pid_t)-1;

	/*
	 * Kernel ABI: sys_getpgid returns task_pgrp_vnr(p) — a positive pid in
	 * the caller's pid_ns, bounded by PID_MAX_LIMIT (4194304). Failure
	 * returns -1 with errno set (-1UL on the syscall return path). A retval
	 * outside [1, PID_MAX_LIMIT] that isn't -1UL is a corrupted retval (a
	 * sign-extension tear, a -errno leaking through the return path, or a
	 * pid_ns translation bug) — reject it before the ONE_IN(100) sample
	 * gates the procfs NSpgid: cross-check, so corruption fires on every
	 * call rather than the 1-in-100 sample.
	 */
	if ((rec->retval < 1UL || rec->retval > 4194304UL) &&
	    rec->retval != (unsigned long)-1L) {
		output(0, "post_getpgid: rejected returned pgid 0x%lx outside [1, PID_MAX_LIMIT=4194304] (and not -1)\n",
		       rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	if (rec->a1 != 0)
		return;

	got = (pid_t) rec->retval;
	if (got == (pid_t)-1)
		return;

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
		output(0, "getpgid oracle: getpgid(0)=%d but "
		       "/proc/self/status NSpgid=%d\n",
		       got, proc_pgid);
		__atomic_add_fetch(&shm->stats.getpgid_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getpgid = {
	.name = "getpgid",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid" },
	.rettype = RET_PID_T,
	.post = post_getpgid,
};
