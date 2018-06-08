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


/*
 * SYSCALL_DEFINE2(setreuid16, old_uid_t, ruid, old_uid_t, euid)
 */

struct syscallentry syscall_setreuid16 = {
	.name = "setreuid16",
	.num_args = 2,
	.arg1name = "ruid",
	.arg2name = "euid",
};
