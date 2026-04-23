/*
 * SYSCALL_DEFINE3(setpriority, int, which, int, who, int, niceval)
 */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

static unsigned long setpriority_which[] = {
	PRIO_PROCESS, PRIO_PGRP, PRIO_USER,
};

static void sanitise_setpriority(struct syscallrecord *rec)
{
	rec->a3 = (unsigned long)((rand() % 40) - 20);	/* -20 to 19 */
}

static void post_setpriority(struct syscallrecord *rec)
{
	FILE *f;
	char line[128];
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
	if ((int) rec->a1 != PRIO_PROCESS)
		return;
	who = (pid_t)(int) rec->a2;
	if (who != 0 && who != getpid())
		return;
	if (!ONE_IN(100))
		return;

	expected = (int) rec->a3;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Nice:", 5) == 0) {
			sscanf(line + 5, "%d", &got);
			break;
		}
	}
	fclose(f);

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
};
