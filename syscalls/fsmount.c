/*
 *  SYSCALL_DEFINE3(fsmount, int, fs_fd, unsigned int, flags, unsigned int, attr_flags)
 */
#include "sanitise.h"

#define FSMOUNT_CLOEXEC         0x00000001
static unsigned long fsmount_flags[] = {
	FSMOUNT_CLOEXEC,
};

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY	0x00000001
#define MOUNT_ATTR_NOSUID	0x00000002
#define MOUNT_ATTR_NODEV	0x00000004
#define MOUNT_ATTR_NOEXEC	0x00000008
#define MOUNT_ATTR_NOATIME	0x00000010
#define MOUNT_ATTR_STRICTATIME	0x00000020
#define MOUNT_ATTR_NODIRATIME	0x00000080
#define MOUNT_ATTR_IDMAP	0x00100000
#define MOUNT_ATTR_NOSYMFOLLOW	0x00200000
#endif

static unsigned long fsmount_attr_flags[] = {
	MOUNT_ATTR_RDONLY,
	MOUNT_ATTR_NOSUID,
	MOUNT_ATTR_NODEV,
	MOUNT_ATTR_NOEXEC,
	MOUNT_ATTR_NOATIME,
	MOUNT_ATTR_STRICTATIME,
	MOUNT_ATTR_NODIRATIME,
	MOUNT_ATTR_IDMAP,
	MOUNT_ATTR_NOSYMFOLLOW,
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
	.rettype = RET_FD,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
