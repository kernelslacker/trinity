/*
 * SYSCALL_DEFINE1(syncfs, int, fd)
 */
#include "sanitise.h"

struct syscallentry syscall_syncfs = {
	.name = "syncfs",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | EXPENSIVE,
	.group = GROUP_VFS,
};
