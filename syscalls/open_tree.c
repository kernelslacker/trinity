/*
 *  SYSCALL_DEFINE3(open_tree, int, dfd, const char *, filename, unsigned, flags)
 */
#include <fcntl.h>
#include "compat.h"
#include "kernel/mount.h"
#include "object-types.h"
#include "sanitise.h"

static unsigned long open_tree_flags[] = {
	AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW,
	OPEN_TREE_CLONE, OPEN_TREE_CLOEXEC, OPEN_TREE_NAMESPACE,
};

struct syscallentry syscall_open_tree = {
	.name = "open_tree",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "dfd", [1] = "filename", [2] = "flags" },
	.arg_params[2].list = ARGLIST(open_tree_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_MOUNT,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.post = post_mount_fd,
};
