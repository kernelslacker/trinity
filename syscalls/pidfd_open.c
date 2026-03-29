/*
 * SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
 */
#include <linux/pidfd.h>
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
	PIDFD_NONBLOCK, PIDFD_THREAD,
};

struct syscallentry syscall_pidfd_open = {
	.name = "pidfd_open",
	.group = GROUP_PROCESS,
	.num_args = 2,
	.argtype = { [0] = ARG_PID, [1] = ARG_LIST },
	.argname = { [0] = "pid", [1] = "flags" },
	.arg2list = ARGLIST(pidfd_open_flags),
	.rettype = RET_FD,
	.post = post_pidfd_open,
};
