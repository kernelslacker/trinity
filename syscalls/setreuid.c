/*
 * SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
 */
#include "sanitise.h"

struct syscallentry syscall_setreuid = {
	.name = "setreuid",
	.num_args = 2,
	.arg1name = "ruid",
	.arg2name = "euid",
};
