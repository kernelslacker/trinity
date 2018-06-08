/*
 * SYSCALL_DEFINE1(setgid, gid_t, gid)
 */
#include "sanitise.h"

struct syscallentry syscall_setgid = {
	.name = "setgid",
	.num_args = 1,
	.arg1name = "gid",
};


/*
 * SYSCALL_DEFINE1(setgid16, old_gid_t, gid)
 */

struct syscallentry syscall_setgid16 = {
	.name = "setgid16",
	.num_args = 1,
	.arg1name = "gid",
};
