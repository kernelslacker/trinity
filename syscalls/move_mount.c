/*
 *  SYSCALL_DEFINE5(move_mount, int, from_dfd, const char *, from_pathname,
 *     int, to_dfd, const char *, to_pathname,  unsigned int, flags)
 */
#include "sanitise.h"

#define MOVE_MOUNT_F_SYMLINKS           0x00000001 /* Follow symlinks on from path */
#define MOVE_MOUNT_F_AUTOMOUNTS         0x00000002 /* Follow automounts on from path */
#define MOVE_MOUNT_F_EMPTY_PATH         0x00000004 /* Empty from path permitted */
#define MOVE_MOUNT_T_SYMLINKS           0x00000010 /* Follow symlinks on to path */
#define MOVE_MOUNT_T_AUTOMOUNTS         0x00000020 /* Follow automounts on to path */
#define MOVE_MOUNT_T_EMPTY_PATH         0x00000040 /* Empty to path permitted */

static unsigned long move_mount_flags[] = {
	MOVE_MOUNT_F_SYMLINKS, MOVE_MOUNT_F_AUTOMOUNTS, MOVE_MOUNT_F_EMPTY_PATH, MOVE_MOUNT_T_SYMLINKS,
	MOVE_MOUNT_T_AUTOMOUNTS, MOVE_MOUNT_T_EMPTY_PATH,
};

struct syscallentry syscall_move_mount = {
	.name = "move_mount",
	.num_args = 5,
	.arg1name = "from_dfd",
	.arg1type = ARG_FD,
	.arg2name = "from_pathname",
	.arg2type = ARG_PATHNAME,
	.arg3name = "to_dfd",
	.arg3type = ARG_FD,
	.arg4name = "to_pathname",
	.arg4type = ARG_PATHNAME,
	.arg5name = "flags",
	.arg5type = ARG_OP,
	.arg5list = ARGLIST(move_mount_flags),
};
