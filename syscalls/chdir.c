/*
 * SYSCALL_DEFINE1(chdir, const char __user *, filename)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_chdir = {
	.name = "chdir",
	.num_args = 1,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
};
