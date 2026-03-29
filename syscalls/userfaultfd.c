/*
 * SYSCALL_DEFINE1(userfaultfd, int, flags)
 */

#include <fcntl.h>
#include "objects.h"
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
	struct object *new;
	int fd = rec->retval;

	if (fd == -1)
		return;

	new = alloc_object();
	new->userfaultobj.fd = fd;
	new->userfaultobj.flags = rec->a1;
	add_object(new, OBJ_LOCAL, OBJ_FD_USERFAULTFD);
}

struct syscallentry syscall_userfaultfd = {
	.name = "userfaultfd",
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags" },
	.arg_params[0].list = ARGLIST(userfaultfd_flags),
	.flags = NEED_ALARM,
	.rettype = RET_FD,
	.post = post_userfaultfd,
	.group = GROUP_VM,
};
