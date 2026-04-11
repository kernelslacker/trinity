/*
 * SYSCALL_DEFINE5(open_tree_attr, int, dfd, const char __user *, filename,
 *		unsigned, flags, struct mount_attr __user *, uattr, size_t, usize)
 */
#include <fcntl.h>
#include <unistd.h>
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

static void post_open_tree_attr(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd != -1)
		close(fd);
}

struct syscallentry syscall_open_tree_attr = {
	.name = "open_tree_attr",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST, [3] = ARG_ADDRESS, [4] = ARG_LEN },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags", [3] = "uattr", [4] = "usize" },
	.arg_params[2].list = ARGLIST(open_tree_attr_flags),
	.rettype = RET_FD,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.post = post_open_tree_attr,
};
