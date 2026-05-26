/*
 * SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
 */
#include <linux/pidfd.h>
#include "publish_resource.h"
#include "sanitise.h"

static void post_pidfd_open(struct syscallrecord *rec)
{
	int fd = rec->retval;
	struct resource_meta meta = { .extra_int = rec->a1 };

	if ((long)rec->retval < 0)
		return;

	publish_resource(OBJ_FD_PIDFD, fd, &meta);
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
	.arg_params[1].list = ARGLIST(pidfd_open_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_PIDFD,
	.post = post_pidfd_open,
};
