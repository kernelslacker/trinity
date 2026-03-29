/*
 * SYSCALL_DEFINE(readahead)(int fd, loff_t offset, size_t count)
 */
#include "sanitise.h"

struct syscallentry syscall_readahead = {
	.name = "readahead",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_LEN, [2] = ARG_LEN },
	.argname = { [0] = "fd", [1] = "offset", [2] = "count" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
