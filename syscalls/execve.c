/*
   long sys_execve(const char __user *name,
	const char __user *const __user *argv,
	const char __user *const __user *envp, struct pt_regs *regs)
 *
 * On success, execve() does not return
 * on error -1 is returned, and errno is set appropriately.
 *
 * TODO: Redirect stdin/stdout.
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_execve = {
	.name = "execve",
	.num_args = 4,
	.arg1name = "name",
	.arg1type = ARG_PATHNAME,
	.arg2name = "argv",
	.arg2type = ARG_ADDRESS,
	.arg3name = "envp",
	.arg3type = ARG_ADDRESS,
	.arg4name = "regs",
	.arg4type = ARG_ADDRESS,
};
