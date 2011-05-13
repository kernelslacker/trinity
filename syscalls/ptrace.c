/*
 * SYSCALL_DEFINE4(ptrace, long, request, long, pid, long, addr, long, data)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_ptrace = {
	.name = "ptrace",
	.num_args = 4,
	.arg1name = "request",
	.arg2name = "pid",
	.arg2type = ARG_PID,
	.arg3name = "addr",
	.arg3type = ARG_ADDRESS,
	.arg4name = "data",
};
