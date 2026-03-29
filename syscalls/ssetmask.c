/*
 * SYSCALL_DEFINE1(ssetmask, int, newmask)
 */
#include "sanitise.h"

struct syscallentry syscall_ssetmask = {
	.name = "ssetmask",
	.num_args = 1,
	.argname = { [0] = "newmask" },
	.group = GROUP_PROCESS,
};
