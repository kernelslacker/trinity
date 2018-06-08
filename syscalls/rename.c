/*
 * SYSCALL_DEFINE2(rename, const char __user *, oldname, const char __user *, newname
 */
#include "sanitise.h"

struct syscallentry syscall_rename = {
	.name = "rename",
	.num_args = 2,
	.arg1name = "oldname",
	.arg1type = ARG_PATHNAME,
	.arg2name = "newname",
	.arg2type = ARG_PATHNAME,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE4(renameat, int, olddfd, const char __user *, oldname,
	 int, newdfd, const char __user *, newname)
 */

struct syscallentry syscall_renameat = {
	.name = "renameat",
	.num_args = 4,
	.arg1name = "olddfd",
	.arg1type = ARG_FD,
	.arg2name = "oldname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "newdfd",
	.arg3type = ARG_FD,
	.arg4name = "newname",
	.arg4type = ARG_PATHNAME,
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
	.arg1name = "olddfd",
	.arg1type = ARG_FD,
	.arg2name = "oldname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "newdfd",
	.arg3type = ARG_FD,
	.arg4name = "newname",
	.arg4type = ARG_PATHNAME,
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = ARGLIST(renameat2_flags),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
