/*
 * SYSCALL_DEFINE1(setfsgid, gid_t, gid)
 */
#include "sanitise.h"

struct syscallentry syscall_setfsgid = {
	.name = "setfsgid",
	.num_args = 1,
	.arg1name = "gid",
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE1(setfsgid16, old_gid_t, gid)
 */

struct syscallentry syscall_setfsgid16 = {
	.name = "setfsgid16",
	.num_args = 1,
	.arg1name = "gid",
	.group = GROUP_VFS,
};
