/*
 * SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid)
 */
#include "sanitise.h"

struct syscallentry syscall_setregid = {
	.name = "setregid",
	.num_args = 2,
	.arg1name = "rgid",
	.arg2name = "egid",
};

/*
 * SYSCALL_DEFINE2(setregid16, old_gid_t, rgid, old_gid_t, egid)
 */

struct syscallentry syscall_setregid16 = {
	.name = "setregid16",
	.num_args = 2,
	.arg1name = "rgid",
	.arg2name = "egid",
};
