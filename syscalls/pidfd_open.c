/*
 * SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
 */
#include "objects.h"
#include "sanitise.h"

static void post_pidfd_open(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if (fd == -1)
		return;

	new = alloc_object();
	new->pidfdobj.fd = fd;
	new->pidfdobj.pid = rec->a1;
	add_object(new, OBJ_LOCAL, OBJ_FD_PIDFD);
}

static unsigned long pidfd_open_flags[] = {
	0,
};

struct syscallentry syscall_pidfd_open = {
	.name = "pidfd_open",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.arg1type = ARG_PID,
	.arg1name = "pid",
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(pidfd_open_flags),
	.rettype = RET_FD,
	.post = post_pidfd_open,
};
