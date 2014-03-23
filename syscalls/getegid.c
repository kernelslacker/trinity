/*
 * SYSCALL_DEFINE0(getegid)
 */
#include "sanitise.h"

struct syscallentry syscall_getegid = {
	.name = "getegid",
	.num_args = 0,
	.rettype = RET_GID_T,
};

/*
 * SYSCALL_DEFINE0(getegid16)
 */

struct syscallentry syscall_getegid16 = {
	.name = "getegid16",
	.num_args = 0,
	.rettype = RET_GID_T,
};
