/*
 * SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
	 int, options, struct rusage __user *, ru)
 */
#include <sys/resource.h>
#include <sys/wait.h>
#include "sanitise.h"

static unsigned long wait_options[] = {
	WNOHANG, WUNTRACED, WCONTINUED, __WALL, __WCLONE,
};

static void sanitise_wait4(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a2, sizeof(int));
	avoid_shared_buffer(&rec->a4, sizeof(struct rusage));
}

struct syscallentry syscall_wait4 = {
	.name = "wait4",
	.group = GROUP_PROCESS,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_ADDRESS, [2] = ARG_LIST, [3] = ARG_ADDRESS },
	.argname = { [0] = "upid", [1] = "stat_addr", [2] = "options", [3] = "ru" },
	.arg_params[2].list = ARGLIST(wait_options),
	.sanitise = sanitise_wait4,
};
