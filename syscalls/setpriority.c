/*
 * SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "pids.h"

static unsigned long setpriority_which[] = {
	PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
};

/*
 * setpriority(which, who, niceval): the kernel rejects an unknown
 * `which` outright with -EINVAL (set_one_prio_perm() / __pri_*) and an
 * unresolvable `who` with -ESRCH before reaching the actual nice-value
 * application path.  Marry the framework's curated `which` pick to a
 * `who` value that resolves for that class:
 *
 *   PRIO_PROCESS -> 0 or our own pid (always live).
 *   PRIO_PGRP    -> 0 or our own pgrp.
 *   PRIO_USER    -> 0 or our own uid.
 *
 * niceval stays in -20..19 most of the time so the can_nice() /
 * security_task_setnice() check runs against a clamped value; a small
 * out-of-range bucket exercises the kernel's MIN_NICE/MAX_NICE clamp
 * in set_user_nice().
 */
static void sanitise_setpriority(struct syscallrecord *rec)
{
	unsigned int which_bucket = rnd_modulo_u32(10);

	if (which_bucket < 8) {
		/* 80%: match `who` to the framework's `which` pick. */
		switch ((int) rec->a1) {
		case PRIO_PROCESS:
			if (RAND_BOOL())
				rec->a2 = 0;
			else
				rec->a2 = (unsigned long) mypid();
			break;
		case PRIO_PGRP:
			if (RAND_BOOL())
				rec->a2 = 0;
			else
				rec->a2 = (unsigned long) getpgrp();
			break;
		case PRIO_USER:
			if (RAND_BOOL())
				rec->a2 = 0;
			else
				rec->a2 = (unsigned long) getuid();
			break;
		default:
			/* framework pick fell outside the curated list (rare). */
			break;
		}
	}
	/* remaining 20%: leave a1/a2 alone for the random tail. */

	if (ONE_IN(10)) {
		/* out-of-range bucket: exercise set_user_nice() clamp. */
		rec->a3 = (unsigned long)(long)((int) rnd_modulo_u32(4096) - 2048);
	} else {
		rec->a3 = (unsigned long)((rnd_modulo_u32(40)) - 20);	/* -20 to 19 */
	}
}

static void post_setpriority(struct syscallrecord *rec)
{
	int which_in = (int) rec->a1;
	pid_t who_in = (pid_t)(int) rec->a2;
	int nice_in = (int) rec->a3;
	char buf[2048];
	char *line;
	ssize_t n;
	int fd;
	int got = INT_MIN;
	int expected;
	pid_t who;

	/*
	 * Oracle: when setpriority(PRIO_PROCESS, self, niceval) returns 0
	 * the kernel's static_prio update must be observable in
	 * /proc/self/status's "Nice:" line.  A mismatch means the kernel
	 * acked the priority change but the on-task value diverged from
	 * what we asked for — silent corruption of a scheduler input.
	 *
	 * Restricted to which==PRIO_PROCESS targeting self (who==0 or our
	 * own pid) so the readback path is deterministic — the other
	 * which-flavours fan out to a pgrp/uid set we can't trivially
	 * enumerate from /proc/self.
	 */
	if ((long) rec->retval != 0)
		return;
	if (which_in != PRIO_PROCESS)
		return;
	who = who_in;
	if (who != 0 && who != mypid())
		return;
	if (!ONE_IN(100))
		return;

	expected = nice_in;

	/*
	 * Mirror the kernel's MIN_NICE/MAX_NICE clamp at the syscall entry:
	 * sys_setpriority clamps niceval into [-20, 19] BEFORE applying it,
	 * so a fuzzed out-of-range niceval still succeeds and the on-task
	 * Nice value will be the clamped result, not the raw input.  Without
	 * this clamp the oracle false-fires for every out-of-range sample.
	 */
	if (expected < -20)
		expected = -20;
	if (expected > 19)
		expected = 19;

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
	/* Anchor on a newline so a "Nice:" substring inside an earlier field
	 * (e.g. a process name) cannot mis-target the parse. */
	line = strstr(buf, "\nNice:");
	if (line != NULL)
		(void) sscanf(line + 6, "%d", &got);

	if (got == INT_MIN)
		return;

	if (got != expected) {
		output(0, "sched oracle: setpriority(PRIO_PROCESS, %d, %d) "
		       "succeeded but /proc/self/status Nice=%d\n",
		       (int) who, expected, got);
		__atomic_add_fetch(&shm->stats.sched_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setpriority = {
	.name = "setpriority",
	.num_args = 3,
	.argtype = { [0] = ARG_OP, [1] = ARG_PID },
	.argname = { [0] = "which", [1] = "who", [2] = "niceval" },
	.arg_params[0].list = ARGLIST(setpriority_which),
	.sanitise = sanitise_setpriority,
	.post = post_setpriority,
	.group = GROUP_SCHED,
	.rettype = RET_ZERO_SUCCESS,
};
