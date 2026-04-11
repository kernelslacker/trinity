/*
 * SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)
 */
#include <linux/sched.h>
#include "sanitise.h"

static unsigned long unshare_flags[] = {
	CLONE_THREAD, CLONE_FS, CLONE_NEWNS, CLONE_SIGHAND,
	CLONE_VM, CLONE_FILES, CLONE_SYSVSEM, CLONE_NEWUTS,
	CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWUSER, CLONE_NEWPID,
	CLONE_NEWCGROUP, CLONE_NEWTIME,
};

struct syscallentry syscall_unshare = {
	.name = "unshare",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "unshare_flags" },
	.arg_params[0].list = ARGLIST(unshare_flags),
	.rettype = RET_ZERO_SUCCESS,
};
