/*
 * SYSCALL_DEFINE0(getgid)
 */
#include "sanitise.h"

struct syscallentry syscall_getgid = {
	.name = "getgid",
	.num_args = 0,
	.rettype = RET_GID_T,
};


/*
 * SYSCALL_DEFINE0(getgid)
 */

struct syscallentry syscall_getgid16 = {
	.name = "getgid16",
	.num_args = 0,
	.rettype = RET_GID_T,
};
