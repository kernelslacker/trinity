/*
 * SYSCALL_DEFINE0(getpgrp)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_getpgrp = {
	.name = "getpgrp",
	.num_args = 0,
	.rettype = RET_PID_T,
};
