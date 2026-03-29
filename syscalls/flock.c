/*
 * SYSCALL_DEFINE2(flock, unsigned int, fd, unsigned int, cmd)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/file.h>
#include "sanitise.h"

static unsigned long flock_cmds[] = {
	LOCK_SH, LOCK_EX, LOCK_UN,
	LOCK_SH | LOCK_NB, LOCK_EX | LOCK_NB,
};

struct syscallentry syscall_flock = {
	.name = "flock",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "cmd" },
	.arg2list = ARGLIST(flock_cmds),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
