/*
 *  SYSCALL_DEFINE5(move_mount, int, from_dfd, const char *, from_pathname,
 *     int, to_dfd, const char *, to_pathname,  unsigned int, flags)
 */
#include "sanitise.h"
#include "compat.h"

static unsigned long move_mount_flags[] = {
	MOVE_MOUNT_F_SYMLINKS, MOVE_MOUNT_F_AUTOMOUNTS, MOVE_MOUNT_F_EMPTY_PATH, MOVE_MOUNT_T_SYMLINKS,
	MOVE_MOUNT_T_AUTOMOUNTS, MOVE_MOUNT_T_EMPTY_PATH,
	MOVE_MOUNT_SET_GROUP, MOVE_MOUNT_BENEATH,
};

struct syscallentry syscall_move_mount = {
	.name = "move_mount",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_MOUNT, [1] = ARG_PATHNAME, [2] = ARG_FD_MOUNT, [3] = ARG_PATHNAME, [4] = ARG_OP },
	.argname = { [0] = "from_dfd", [1] = "from_pathname", [2] = "to_dfd", [3] = "to_pathname", [4] = "flags" },
	.arg_params[4].list = ARGLIST(move_mount_flags),
	.group = GROUP_VFS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEEDS_ROOT,
};
