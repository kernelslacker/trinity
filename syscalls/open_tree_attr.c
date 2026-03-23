/*
 * SYSCALL_DEFINE5(open_tree_attr, int, dfd, const char __user *, filename,
 *		unsigned, flags, struct mount_attr __user *, uattr, size_t, usize)
 */
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE		1
#define OPEN_TREE_CLOEXEC	O_CLOEXEC
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE		0x8000
#endif

static unsigned long open_tree_attr_flags[] = {
	AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW,
	OPEN_TREE_CLONE, OPEN_TREE_CLOEXEC,
};

struct syscallentry syscall_open_tree_attr = {
	.name = "open_tree_attr",
	.num_args = 5,
	.arg1name = "dfd",
	.arg1type = ARG_FD,
	.arg2name = "filename",
	.arg2type = ARG_PATHNAME,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(open_tree_attr_flags),
	.arg4name = "uattr",
	.arg4type = ARG_ADDRESS,
	.arg5name = "usize",
	.arg5type = ARG_LEN,
	.rettype = RET_FD,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
