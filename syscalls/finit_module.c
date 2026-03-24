/*
 * SYSCALL_DEFINE3(finit_module, int, fd, const char __user *, uargs, int, flags)
 */
#include "sanitise.h"

#ifndef MODULE_INIT_IGNORE_MODVERSIONS
#define MODULE_INIT_IGNORE_MODVERSIONS  1
#endif
#ifndef MODULE_INIT_IGNORE_VERMAGIC
#define MODULE_INIT_IGNORE_VERMAGIC     2
#endif
#ifndef MODULE_INIT_COMPRESSED_FILE
#define MODULE_INIT_COMPRESSED_FILE     4
#endif

static unsigned long finit_module_flags[] = {
	MODULE_INIT_IGNORE_MODVERSIONS, MODULE_INIT_IGNORE_VERMAGIC,
	MODULE_INIT_COMPRESSED_FILE,
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
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
};
