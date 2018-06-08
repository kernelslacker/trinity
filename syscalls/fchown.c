/*
 * SYSCALL_DEFINE3(fchown, unsigned int, fd, uid_t, user, gid_t, group)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_fchown = {
	.name = "fchown",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "user",
	.arg3name = "group",
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE3(fchown16, unsigned int, fd, old_uid_t, user, old_gid_t, group)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_fchown16 = {
	.name = "fchown16",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "user",
	.arg3name = "group",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE5(fchownat, int, dfd, const char __user *, filename, uid_t, user,
	gid_t, group, int, flag)
 *
 * On success, fchownat() returns 0.
 *  On error, -1 is returned and errno is set to indicate the error.
 */

struct syscallentry syscall_fchownat = {
	.name = "fchownat",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "user",
	.arg4name = "group",
	.arg5name = "flag",
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
