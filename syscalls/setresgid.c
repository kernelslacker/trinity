/*
 * SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
 */
#include "sanitise.h"

struct syscallentry syscall_setresgid = {
	.name = "setresgid",
	.num_args = 3,
	.arg1name = "rgid",
	.arg2name = "egid",
	.arg3name = "sgid",
};


/*
 * SYSCALL_DEFINE3(setresgid16, old_gid_t, rgid, old_gid_t, egid, old_gid_t, sgid)
 */

struct syscallentry syscall_setresgid16 = {
	.name = "setresgid16",
	.num_args = 3,
	.arg1name = "rgid",
	.arg2name = "egid",
	.arg3name = "sgid",
};
