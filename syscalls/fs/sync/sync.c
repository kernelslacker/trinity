/*
 * SYSCALL_DEFINE0(sync)
 */
#include "sanitise.h"

struct syscallentry syscall_sync = {
	.name = "sync",
	.num_args = 0,
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = AVOID_SYSCALL,	/* whole-system flush, blocks long enough to trip the watchdog regularly */
};
