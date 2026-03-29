/*
 * SYSCALL_DEFINE(fanotify_mark)(int fanotify_fd, unsigned int flags,
	__u64 mask, int dfd, const char  __user * pathname)
 */
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/* flags used for fanotify_modify_mark() */
#define FAN_MARK_ADD            0x00000001
#define FAN_MARK_REMOVE         0x00000002
#define FAN_MARK_DONT_FOLLOW    0x00000004
#define FAN_MARK_ONLYDIR        0x00000008
#define FAN_MARK_MOUNT          0x00000010
#define FAN_MARK_IGNORED_MASK   0x00000020
#define FAN_MARK_IGNORED_SURV_MODIFY    0x00000040
#define FAN_MARK_FLUSH          0x00000080

#define FAN_ACCESS              0x00000001      /* File was accessed */
#define FAN_MODIFY              0x00000002      /* File was modified */
#define FAN_CLOSE_WRITE         0x00000008      /* Writtable file closed */
#define FAN_CLOSE_NOWRITE       0x00000010      /* Unwrittable file closed */
#define FAN_OPEN                0x00000020      /* File was opened */

#define FAN_Q_OVERFLOW          0x00004000      /* Event queued overflowed */

#define FAN_OPEN_PERM           0x00010000      /* File open in perm check */
#define FAN_ACCESS_PERM         0x00020000      /* File accessed in perm check */

#define FAN_ONDIR               0x40000000      /* event occurred against dir */

#define FAN_EVENT_ON_CHILD      0x08000000      /* interested in child events */
#define FAN_CLOSE               (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE) /* close */

static void sanitise_fanotify_mark(struct syscallrecord *rec)
{
	unsigned int flagvals[5] = { FAN_MARK_DONT_FOLLOW, FAN_MARK_ONLYDIR, FAN_MARK_MOUNT,
				    FAN_MARK_IGNORED_MASK, FAN_MARK_IGNORED_SURV_MODIFY };

	unsigned int i;
	unsigned int numflags = rand() % 5;

	// set additional flags
	for (i = 0; i < numflags; i++)
		rec->a2 |= flagvals[i];

	// Set mask
	rec->a3 &= 0xffffffff;
}

static unsigned long fanotify_mark_flags[] = {
	FAN_MARK_ADD, FAN_MARK_REMOVE, FAN_MARK_FLUSH,
};

static unsigned long fanotify_mark_mask[] = {
	FAN_ACCESS, FAN_MODIFY, FAN_CLOSE, FAN_OPEN,
	FAN_OPEN_PERM, FAN_ACCESS_PERM, FAN_EVENT_ON_CHILD,
};

struct syscallentry syscall_fanotify_mark = {
	.name = "fanotify_mark",
	.num_args = 5,
	.argtype = { [0] = ARG_FD_FANOTIFY, [1] = ARG_OP, [2] = ARG_LIST, [3] = ARG_FD, [4] = ARG_PATHNAME },
	.argname = { [0] = "fanotify_fd", [1] = "flags", [2] = "mask", [3] = "dfd", [4] = "pathname" },
	.arg2list = ARGLIST(fanotify_mark_flags),
	.arg3list = ARGLIST(fanotify_mark_mask),
	.sanitise = sanitise_fanotify_mark,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
