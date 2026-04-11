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

static void post_memfd_secret(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd != -1)
		close(fd);
}

struct syscallentry syscall_memfd_secret = {
	.name = "memfd_secret",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flag" },
	.arg_params[0].list = ARGLIST(memfd_secret_flags),
	.rettype = RET_FD,
	.post = post_memfd_secret,
	.group = GROUP_VFS,
};
