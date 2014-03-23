/*
 * SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
 */
#include "sanitise.h"

struct syscallentry syscall_setresuid = {
	.name = "setresuid",
	.num_args = 3,
	.arg1name = "ruid",
	.arg2name = "euid",
	.arg3name = "suid",
};

/*
 * SYSCALL_DEFINE3(setresuid16, old_uid_t, ruid, old_uid_t, euid, old_uid_t, suid)
 */

struct syscallentry syscall_setresuid16 = {
	.name = "setresuid16",
	.num_args = 3,
	.arg1name = "ruid",
	.arg2name = "euid",
	.arg3name = "suid",
};
