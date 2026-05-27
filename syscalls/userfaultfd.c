/*
 * SYSCALL_DEFINE1(userfaultfd, int, flags)
 */

#include <fcntl.h>
#include "publish_resource.h"
#include "sanitise.h"
#include "compat.h"

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif

static unsigned long userfaultfd_flags[] = {
	O_CLOEXEC, O_NONBLOCK, UFFD_USER_MODE_ONLY,
};

static void post_userfaultfd(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd < 0)
		return;

	struct resource_meta meta = { .flags = rec->a1 };
	publish_resource(OBJ_FD_USERFAULTFD, fd, &meta);
}

struct syscallentry syscall_userfaultfd = {
	.name = "userfaultfd",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags" },
	.arg_params[0].list = ARGLIST(userfaultfd_flags),
	.flags = NEED_ALARM,
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_USERFAULTFD,
	.post = post_userfaultfd,
	.group = GROUP_VM,
};
