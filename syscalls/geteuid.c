/*
 * SYSCALL_DEFINE0(geteuid)
 */
#include "sanitise.h"

struct syscallentry syscall_geteuid = {
	.name = "geteuid",
	.num_args = 0,
	.rettype = RET_UID_T,
};


/*
 * SYSCALL_DEFINE0(geteuid16)
 */

struct syscallentry syscall_geteuid16 = {
	.name = "geteuid16",
	.num_args = 0,
	.rettype = RET_UID_T,
};
