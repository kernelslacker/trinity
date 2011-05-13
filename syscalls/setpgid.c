/*
 * SYSCALL_DEFINE2(setpgid, pid_t, pid, pid_t, pgid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_setpgid = {
	.name = "setpgid",
	.num_args = 2,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "pgid",
};
