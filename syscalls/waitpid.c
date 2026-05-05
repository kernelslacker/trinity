/*
 * SYSCALL_DEFINE3(waitpid, pid_t, pid, int __user *, stat_addr, int, options)
 */
#include <sys/wait.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long wait_options[] = {
	WNOHANG, WUNTRACED, WCONTINUED,
};

static void sanitise_waitpid(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(int));
}

/*
 * Kernel ABI: waitpid() returns -1 on error, 0 when WNOHANG is set and no
 * child has changed state, or the reaped child pid in [1, PID_MAX_LIMIT
 * (4194304)] on success. Any other retval is a structural ABI regression
 * (e.g. -errno bleeding through the syscall return path, or a pid_ns
 * translation bug). Mirrors the pid-bound style used in 547498ccfe16
 * (getpgrp) / edc0796b4cd7 (gettid) / 108b67820997 (getppid).
 */
static void post_waitpid(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L || ret == 0)
		return;

	if (ret < 0 || ret > 4194304) {
		output(0, "waitpid oracle: returned pid %ld is out of range (must be -1, 0, or in [1, PID_MAX_LIMIT=4194304])\n",
		       ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_waitpid = {
	.name = "waitpid",
	.group = GROUP_PROCESS,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_ADDRESS, [2] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "stat_addr", [2] = "options" },
	.arg_params[2].list = ARGLIST(wait_options),
	.sanitise = sanitise_waitpid,
	.post = post_waitpid,
};
