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
	.argtype = { [0] = ARG_FD, [1] = ARG_ADDRESS, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "uargs", [2] = "flags" },
	.arg_params[2].list = ARGLIST(finit_module_flags),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
};
