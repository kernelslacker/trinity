/*
 * SYSCALL_DEFINE0(getpgrp)
 */
#include "sanitise.h"

struct syscallentry syscall_getpgrp = {
	.name = "getpgrp",
	.num_args = 0,
	.rettype = RET_PID_T,
};
