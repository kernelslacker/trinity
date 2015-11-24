/*
 * SYSCALL_DEFINE1(userfaultfd, int, flags)
 */

#include <fcntl.h>
#include "sanitise.h"

static unsigned long userfaultfd_flags[] = {
	O_CLOEXEC, O_NONBLOCK,
};

struct syscallentry syscall_userfaultfd = {
	.name = "userfaultfd",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(userfaultfd_flags),
	.flags = NEED_ALARM,
	.rettype = RET_FD,
};
