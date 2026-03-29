/*
 * SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname
 */
#include "sanitise.h"

struct syscallentry syscall_rename = {
	.name = "rename",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_PATHNAME },
	.argname = { [0] = "oldname", [1] = "newname" },
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname,
	 int, newdfd, const char __user *, newname)
 */

struct syscallentry syscall_renameat = {
	.name = "renameat",
	.num_args = 4,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_FD, [3] = ARG_PATHNAME },
	.argname = { [0] = "olddfd", [1] = "oldname", [2] = "newdfd", [3] = "newname" },
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE5(renameat2, int, olddfd, const char __user *, oldname,
		   int, newdfd, const char __user *, newname, unsigned int, flags)
 */

#define RENAME_NOREPLACE        (1 << 0)        /* Don't overwrite target */
#define RENAME_EXCHANGE         (1 << 1)        /* Exchange source and dest */
#define RENAME_WHITEOUT         (1 << 2)	/* Whiteout source */

static unsigned long renameat2_flags[] = {
	RENAME_NOREPLACE, RENAME_EXCHANGE, RENAME_WHITEOUT,
};

struct syscallentry syscall_renameat2 = {
	.name = "renameat2",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_FD, [3] = ARG_PATHNAME, [4] = ARG_LIST },
	.argname = { [0] = "olddfd", [1] = "oldname", [2] = "newdfd", [3] = "newname", [4] = "flags" },
	.arg_params[4].list = ARGLIST(renameat2_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
