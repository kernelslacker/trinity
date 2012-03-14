/*
 * SYSCALL_DEFINE0(getegid)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_getegid = {
	.name = "getegid",
	.num_args = 0,
	.rettype = RET_GID_T,
};
