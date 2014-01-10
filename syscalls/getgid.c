/*
 * SYSCALL_DEFINE0(getgid)
 */
#include "sanitise.h"

struct syscallentry syscall_getgid = {
	.name = "getgid",
	.num_args = 0,
	.rettype = RET_GID_T,
};
