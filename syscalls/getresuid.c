/*
 * SYSCALL_DEFINE3(getresuid, uid_t __user *, ruid, uid_t __user *, euid, uid_t __user *, suid)
 */
#include "sanitise.h"

struct syscallentry syscall_getresuid = {
	.name = "getresuid",
	.num_args = 3,
	.arg1name = "ruid",
	.arg1type = ARG_ADDRESS,
	.arg2name = "euid",
	.arg2type = ARG_ADDRESS,
	.arg3name = "suid",
	.arg3type = ARG_ADDRESS,
};

/*
 * SYSCALL_DEFINE3(getresuid16, old_uid_t __user *, ruid, old_uid_t __user *, euid, old_uid_t __user *, suid)
 */

struct syscallentry syscall_getresuid16 = {
	.name = "getresuid16",
	.num_args = 3,
	.arg1name = "ruid",
	.arg1type = ARG_ADDRESS,
	.arg2name = "euid",
	.arg2type = ARG_ADDRESS,
	.arg3name = "suid",
	.arg3type = ARG_ADDRESS,
};
