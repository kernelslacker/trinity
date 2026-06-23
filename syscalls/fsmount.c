/*
 *  SYSCALL_DEFINE3(fsmount, int, fs_fd, unsigned int, flags, unsigned int, attr_flags)
 */
#include <unistd.h>
#include "compat.h"
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
	.ret_objtype = OBJ_FD_MOUNT,
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT | KCOV_REMOTE_HEAVY,
	.post = post_mount_fd,
};
