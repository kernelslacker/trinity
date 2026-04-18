/*
 * SYSCALL_DEFINE1(memfd_secret, unsigned int, flags)
 */

#include <fcntl.h>
#include <unistd.h>
#include "sanitise.h"
#include "memfd.h"
#include "compat.h"

static unsigned long memfd_secret_flags[] = {
	O_CLOEXEC,
};

struct syscallentry syscall_memfd_secret = {
	.name = "memfd_secret",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flag" },
	.arg_params[0].list = ARGLIST(memfd_secret_flags),
	.rettype = RET_FD,
	.post = generic_post_close_fd,
	.group = GROUP_VFS,
};
