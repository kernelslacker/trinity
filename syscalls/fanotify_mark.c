/*
 * SYSCALL_DEFINE(fanotify_mark)(int fanotify_fd, unsigned int flags,
	__u64 mask, int dfd, const char  __user * pathname)
 */
#include <stdlib.h>
#include <linux/fanotify.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/* Event mask bits added in newer kernels; guard for older toolchains. */
#ifndef FAN_ATTRIB
#define FAN_ATTRIB		0x00000004
#endif
#ifndef FAN_DELETE_SELF
#define FAN_DELETE_SELF		0x00000400
#endif
#ifndef FAN_MOVE_SELF
#define FAN_MOVE_SELF		0x00000800
#endif
#ifndef FAN_OPEN_EXEC
#define FAN_OPEN_EXEC		0x00001000
#endif
#ifndef FAN_OPEN_EXEC_PERM
#define FAN_OPEN_EXEC_PERM	0x00040000
#endif
#ifndef FAN_RENAME
#define FAN_RENAME		0x10000000
#endif
#ifndef FAN_ONDIR
#define FAN_ONDIR		0x40000000
#endif

static void sanitise_fanotify_mark(struct syscallrecord *rec)
{
	static const unsigned int flagvals[] = {
		FAN_MARK_DONT_FOLLOW, FAN_MARK_ONLYDIR, FAN_MARK_MOUNT,
		FAN_MARK_IGNORED_MASK, FAN_MARK_IGNORED_SURV_MODIFY,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(flagvals); i++) {
		if (RAND_BOOL())
			rec->a2 |= flagvals[i];
	}
}

static unsigned long fanotify_mark_flags[] = {
	FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_FLUSH,
};

static unsigned long fanotify_mark_mask[] = {
	FAN_ACCESS, FAN_MODIFY, FAN_ATTRIB,
	FAN_CLOSE, FAN_CLOSE_WRITE, FAN_CLOSE_NOWRITE,
	FAN_OPEN, FAN_OPEN_EXEC,
	FAN_OPEN_PERM, FAN_ACCESS_PERM, FAN_OPEN_EXEC_PERM,
	FAN_EVENT_ON_CHILD, FAN_ONDIR,
	FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF,
	FAN_MOVED_FROM, FAN_MOVED_TO, FAN_MOVE_SELF,
	FAN_RENAME,
};

struct syscallentry syscall_fanotify_mark = {
	.name = "fanotify_mark",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_FANOTIFY, [1] = ARG_OP, [2] = ARG_LIST, [3] = ARG_FD, [4] = ARG_PATHNAME },
	.argname = { [0] = "fanotify_fd", [1] = "flags", [2] = "mask", [3] = "dfd", [4] = "pathname" },
	.arg_params[1].list = ARGLIST(fanotify_mark_flags),
	.arg_params[2].list = ARGLIST(fanotify_mark_mask),
	.sanitise = sanitise_fanotify_mark,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
