/*
 * SYSCALL_DEFINE5(perf_counter_open,
         struct perf_counter_attr __user *, attr_uptr,
         pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_perf_counter_open = {
	.name = "perf_event_open",
	.num_args = 5,
	.arg1name = "attr_uptr",
	.arg1type = ARG_ADDRESS,
	.arg2name = "pid",
	.arg2type = ARG_PID,
	.arg3name = "cpu",
	.arg4name = "group_fd",
	.arg4type = ARG_FD,
	.arg5name = "flags",
};
