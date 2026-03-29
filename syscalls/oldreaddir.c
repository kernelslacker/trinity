/*
 * SYSCALL_DEFINE3(old_readdir, unsigned int, fd,
                 struct old_linux_dirent __user *, dirent, unsigned int, count)
 */
#include "sanitise.h"

struct syscallentry syscall_oldreaddir = {
	.name = "old_readdir",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "dirent", [2] = "count" },
	.group = GROUP_VFS,
};
