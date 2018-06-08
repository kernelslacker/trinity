/*
 * SYSCALL_DEFINE1(setfsuid, uid_t, uid)
 */
#include "sanitise.h"

struct syscallentry syscall_setfsuid = {
	.name = "setfsuid",
	.num_args = 1,
	.arg1name = "uid",
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE1(setfsuid16, old_uid_t, uid)
 */

struct syscallentry syscall_setfsuid16 = {
	.name = "setfsuid16",
	.num_args = 1,
	.arg1name = "uid",
	.group = GROUP_VFS,
};
