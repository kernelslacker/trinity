/*
 *  SYSCALL_DEFINE3(fsmount, int, fs_fd, unsigned int, flags, unsigned int, attr_flags)
 */
#include "sanitise.h"
#include "compat.h"

#define FSMOUNT_CLOEXEC         0x00000001
static unsigned long fsmount_flags[] = {
	FSMOUNT_CLOEXEC,
};

static unsigned long fsmount_attr_flags[] = {
	MOVE_MOUNT_F_SYMLINKS,
	MOVE_MOUNT_F_AUTOMOUNTS,
	MOVE_MOUNT_F_EMPTY_PATH,
	MOVE_MOUNT_T_SYMLINKS,
	MOVE_MOUNT_T_AUTOMOUNTS,
	MOVE_MOUNT_T_EMPTY_PATH,
};


struct syscallentry syscall_fsmount = {
	.name = "fsmount",
	.num_args = 3,
	.arg1name = "fs_fd",
	.arg1type = ARG_FD,
	.arg2name = "flags",
	.arg2type = ARG_OP,
	.arg2list = ARGLIST(fsmount_flags),
	.arg3name = "attr_flags",
	.arg3type = ARG_OP,
	.arg3list = ARGLIST(fsmount_attr_flags),
};
