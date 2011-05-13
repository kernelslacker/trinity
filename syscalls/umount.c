/*
 * SYSCALL_DEFINE2(umount, char __user *, name, int, flags)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_umount = {
	.name = "umount",
	.num_args = 2,
	.arg1name = "name",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
};
