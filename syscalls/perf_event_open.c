/*
 * SYSCALL_DEFINE5(perf_event_open,
	 struct perf_event_attr __user *, attr_uptr,
	 pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
 */
#define PERF_FLAG_FD_NO_GROUP   (1U << 0)
#define PERF_FLAG_FD_OUTPUT     (1U << 1)
#define PERF_FLAG_PID_CGROUP    (1U << 2) /* pid=cgroup id, per-cpu mode only */

#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_perf_event_open = {
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
	.arg5type = ARG_LIST,
	.arg5list = {
		.num = 3,
		.values = { PERF_FLAG_FD_NO_GROUP, PERF_FLAG_FD_OUTPUT, PERF_FLAG_PID_CGROUP },
	},
};
