/*
 * SYSCALL_DEFINE2(umount, char __user *, name, int, flags)
 */
#include <sys/mount.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long umount_flags[] = {
	MNT_FORCE, MNT_DETACH, MNT_EXPIRE, UMOUNT_NOFOLLOW,
};

struct syscallentry syscall_umount = {
	.name = "umount",
	.num_args = 2,
	.argtype = { [0] = ARG_PATHNAME, [1] = ARG_LIST },
	.argname = { [0] = "name", [1] = "flags" },
	.arg2list = ARGLIST(umount_flags),
	.group = GROUP_VFS,
	.flags = NEEDS_ROOT,
};
