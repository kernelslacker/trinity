/*
 * SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_kill = {
	.name = "kill",
	.num_args = 2,
	.arg1name = "pid",
	.arg1type = ARG_PID,
	.arg2name = "sig",
	.flags = AVOID_SYSCALL,
};
