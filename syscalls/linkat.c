/*
 * SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname,
	 int, newdfd, const char __user *, newname, int, flags)
 */
#include <fcntl.h>
#include <stdlib.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "compat.h"

static void sanitise_linkat(struct syscallrecord *rec)
{
	/* .. If oldpath is relative and olddirfd is the special value AT_FDCWD, then oldpath is
	 * interpreted relative to the current working directory of the calling process  */
	if (ONE_IN(100))
		rec->a1 = AT_FDCWD;
}

static unsigned long linkat_flags[] = {
	AT_SYMLINK_FOLLOW , AT_EMPTY_PATH,
};

struct syscallentry syscall_linkat = {
	.name = "linkat",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_FD, [3] = ARG_PATHNAME, [4] = ARG_LIST },
	.argname = { [0] = "olddfd", [1] = "oldname", [2] = "newdfd", [3] = "newname", [4] = "flags" },
	.arg_params[4].list = ARGLIST(linkat_flags),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
	.sanitise = sanitise_linkat,
};
