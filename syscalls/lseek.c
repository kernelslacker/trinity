/*
 * SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
 */
#include <sys/types.h>
#include <unistd.h>
#include "sanitise.h"
#include "compat.h"

struct syscallentry syscall_lseek = {
	.name = "lseek",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset",
	.arg3name = "whence",
	.arg3type = ARG_OP,
	.arg3list = {
		.num = 5,
		.values = { SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE, },
	},
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
