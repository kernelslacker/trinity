/*
 * SYSCALL_DEFINE3(inotify_add_watch, int, fd, const char __user *, pathname, u32, mask)
 */
#include "sanitise.h"
#include "compat.h"

#include <sys/inotify.h>

static unsigned long inotify_add_watch_masks[] = {
	IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE,
	IN_CLOSE_NOWRITE, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO,
	IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF,
	IN_UNMOUNT, IN_Q_OVERFLOW, IN_IGNORED, IN_ONLYDIR,
	IN_DONT_FOLLOW, IN_EXCL_UNLINK, IN_MASK_ADD, IN_ISDIR,
	IN_ONESHOT, IN_MASK_CREATE,
};

struct syscallentry syscall_inotify_add_watch = {
	.name = "inotify_add_watch",
	.num_args = 3,
	.argtype = { [0] = ARG_FD_INOTIFY, [1] = ARG_PATHNAME, [2] = ARG_LIST },
	.argname = { [0] = "fd", [1] = "pathname", [2] = "mask" },
	.arg_params[2].list = ARGLIST(inotify_add_watch_masks),
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
