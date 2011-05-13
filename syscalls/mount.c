/*
 * SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
	 char __user *, type, unsigned long, flags, void __user *, data)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_mount = {
	.name = "mount",
	.num_args = 5,
	.arg1name = "dev_name",
	.arg1type = ARG_ADDRESS,
	.arg2name = "dir_name",
	.arg2type = ARG_ADDRESS,
	.arg3name = "type",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
	.arg5name = "data",
	.arg5type = ARG_ADDRESS,
};
