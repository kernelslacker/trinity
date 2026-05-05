/*
 * SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
	 int, options, struct rusage __user *, ru)
 */
#include <sys/resource.h>
#include <sys/wait.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long wait_options[] = {
	WNOHANG, WUNTRACED, WCONTINUED, __WALL, __WCLONE,
};

static void sanitise_wait4(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(int));
	avoid_shared_buffer(&rec->a4, sizeof(struct rusage));
}

/*
 * Kernel ABI: wait4() returns -1 on error, 0 when WNOHANG is set and no
 * child has changed state, or the reaped child pid in [1, PID_MAX_LIMIT
 * (4194304)] on success. *stat_addr and *ru are separate concerns; only
 * the retval is bound-checked here. Mirrors the pid-bound style used in
 * 547498ccfe16 (getpgrp) / edc0796b4cd7 (gettid) / 108b67820997 (getppid).
 */
static void post_wait4(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L || ret == 0)
		return;

	if (ret < 0 || ret > 4194304) {
		output(0, "wait4 oracle: returned pid %ld is out of range (must be -1, 0, or in [1, PID_MAX_LIMIT=4194304])\n",
		       ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_wait4 = {
	.name = "wait4",
	.group = GROUP_PROCESS,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_ADDRESS, [2] = ARG_LIST, [3] = ARG_ADDRESS },
	.argname = { [0] = "upid", [1] = "stat_addr", [2] = "options", [3] = "ru" },
	.arg_params[2].list = ARGLIST(wait_options),
	.sanitise = sanitise_wait4,
	.post = post_wait4,
};
