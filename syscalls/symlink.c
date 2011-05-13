/*
 * SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_symlink = {
	.name = "symlink",
	.num_args = 2,
	.arg1name = "oldname",
	.arg1type = ARG_ADDRESS,
	.arg2name = "newname",
	.arg2type = ARG_ADDRESS,
};
