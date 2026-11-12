/*
 * SYSCALL_DEFINE2(pidfd_open, pid_t, pid, unsigned int, flags)
 */
#include <linux/pidfd.h>
#include "fd.h"
#include "objects.h"
#include "sanitise.h"

/* Same refusal contract as post_mount_fd(). */
static void post_pidfd_open(struct syscallrecord *rec)
{
	long fd = (long) rec->retval;

	if (fd < 0 || fd >= FD_NR_MAX)
		return;

	if (pool_typed_fd(OBJ_FD_PIDFD, (int) fd) == NULL)
		rec->retval = -1UL;
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
