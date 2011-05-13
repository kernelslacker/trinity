/*
 * SYSCALL_DEFINE3(chown, const char __user *, filename, uid_t, user, gid_t, group)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_chown = {
	.name = "chown",
	.num_args = 3,
	.arg1name = "filename",
	.arg1type = ARG_ADDRESS,
	.arg2name = "user",
	.arg3name = "group",
};
