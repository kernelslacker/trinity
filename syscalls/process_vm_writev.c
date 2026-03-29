/*
 * SYSCALL_DEFINE6(process_vm_writev, pid_t, pid, const struct iovec __user *, lvec,
 *                unsigned long, liovcnt, const struct iovec __user *, rvec,
 *                unsigned long, riovcnt, unsigned long, flags)
 */
#include "sanitise.h"

static unsigned long process_vm_writev_flags[] = {
	0,	// currently no flags defined, mbz
};

struct syscallentry syscall_process_vm_writev = {
	.name = "process_vm_writev",
	.group = GROUP_PROCESS,
	.num_args = 6,
	.argtype = { [0] = ARG_PID, [1] = ARG_IOVEC, [2] = ARG_IOVECLEN, [3] = ARG_IOVEC, [4] = ARG_IOVECLEN, [5] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "lvec", [2] = "liovcnt", [3] = "rvec", [4] = "riovcnt", [5] = "flags" },
	.arg6list = ARGLIST(process_vm_writev_flags),
};
