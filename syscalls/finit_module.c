/*
 * SYSCALL_DEFINE3(finit_module, int, fd, const char __user *, uargs, int, flags)
 */
#include "sanitise.h"

#define MODULE_INIT_IGNORE_MODVERSIONS  1
#define MODULE_INIT_IGNORE_VERMAGIC     2

static unsigned long finit_module_flags[] = {
	MODULE_INIT_IGNORE_MODVERSIONS, MODULE_INIT_IGNORE_VERMAGIC,
};

struct syscallentry syscall_finit_module = {
	.name = "finit_module",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "uargs",
	.arg2type = ARG_ADDRESS,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(finit_module_flags),
};
