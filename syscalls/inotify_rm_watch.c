/*
 * SYSCALL_DEFINE2(inotify_rm_watch, int, fd, __s32, wd)
 */
#include "random.h"
#include "sanitise.h"

static void sanitise_inotify_rm_watch(struct syscallrecord *rec)
{
	/*
	 * Watch descriptors are small positive integers allocated
	 * sequentially starting at 1. arm_inotify() adds 1-3
	 * watches per fd, so valid wd values are typically 1-10.
	 * Generate small values to have a chance of hitting real watches.
	 */
	rec->a2 = 1 + (rand() % 10);
}

struct syscallentry syscall_inotify_rm_watch = {
	.name = "inotify_rm_watch",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD_INOTIFY,
	.arg2name = "wd",
	.sanitise = sanitise_inotify_rm_watch,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
