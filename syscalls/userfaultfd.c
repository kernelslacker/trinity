/*
 * SYSCALL_DEFINE1(userfaultfd, int, flags)
 */

#include <fcntl.h>
#include "sanitise.h"

struct syscallentry syscall_userfaultfd = {
	.name = "userfaultfd",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 2,
		.values = { O_CLOEXEC, O_NONBLOCK, },
	},
	.flags = NEED_ALARM,
	.rettype = RET_FD,
};
