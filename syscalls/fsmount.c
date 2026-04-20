/*
 *  SYSCALL_DEFINE3(fsmount, int, fs_fd, unsigned int, flags, unsigned int, attr_flags)
 */
#include <unistd.h>
#include "object-types.h"
#include "sanitise.h"

#define FSMOUNT_CLOEXEC         0x00000001
/* FSMOUNT_NAMESPACE added in Linux v7.1 merge window. */
#ifndef FSMOUNT_NAMESPACE
#define FSMOUNT_NAMESPACE	0x00000002
#endif

static unsigned long fsmount_flags[] = {
	FSMOUNT_CLOEXEC,
	FSMOUNT_NAMESPACE,
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
	.argtype = { [0] = ARG_FD_FS_CTX, [1] = ARG_OP, [2] = ARG_OP },
	.argname = { [0] = "fs_fd", [1] = "flags", [2] = "attr_flags" },
	.arg_params[1].list = ARGLIST(fsmount_flags),
	.arg_params[2].list = ARGLIST(fsmount_attr_flags),
	.rettype = RET_FD,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
	.post = generic_post_close_fd,
};
