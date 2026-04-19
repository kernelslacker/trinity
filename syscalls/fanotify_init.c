/*
 * SYSCALL_DEFINE2(fanotify_init, unsigned int, flags, unsigned int, event_f_flags)
 */

#define FAN_CLOEXEC		0x00000001
#define FAN_NONBLOCK		0x00000002
#define FAN_CLASS_NOTIF		0x00000000
#define FAN_CLASS_CONTENT	0x00000004
#define FAN_CLASS_PRE_CONTENT	0x00000008
#define FAN_UNLIMITED_QUEUE	0x00000010
#define FAN_UNLIMITED_MARKS	0x00000020

/* FID-based reporting flags (5.1+); guard in case headers already define them. */
#ifndef FAN_REPORT_TID
#define FAN_REPORT_TID		0x00000100
#endif
#ifndef FAN_REPORT_FID
#define FAN_REPORT_FID		0x00000200
#endif
#ifndef FAN_REPORT_DIR_FID
#define FAN_REPORT_DIR_FID	0x00000400
#endif
#ifndef FAN_REPORT_NAME
#define FAN_REPORT_NAME		0x00000800
#endif
#ifndef FAN_REPORT_TARGET_FID
#define FAN_REPORT_TARGET_FID	0x00001000
#endif
#ifndef FAN_REPORT_PIDFD
#define FAN_REPORT_PIDFD	0x00000080
#endif
#ifndef FAN_REPORT_FD_ERROR
#define FAN_REPORT_FD_ERROR	0x00002000
#endif
#ifndef FAN_REPORT_MNT
#define FAN_REPORT_MNT		0x00004000
#endif
#ifndef FAN_ENABLE_AUDIT
#define FAN_ENABLE_AUDIT	0x00000040
#endif

#include <fcntl.h>
#include "fanotify.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"

static unsigned long fanotify_init_flags[] = {
	FAN_CLOEXEC, FAN_NONBLOCK, FAN_UNLIMITED_QUEUE, FAN_UNLIMITED_MARKS,
	FAN_CLASS_NOTIF, FAN_CLASS_CONTENT, FAN_CLASS_PRE_CONTENT,
	FAN_REPORT_TID, FAN_REPORT_FID, FAN_REPORT_DIR_FID, FAN_REPORT_NAME,
	FAN_REPORT_TARGET_FID, FAN_REPORT_PIDFD, FAN_REPORT_FD_ERROR,
	FAN_REPORT_MNT, FAN_ENABLE_AUDIT,
};

unsigned long get_fanotify_init_flags(void)
{
	return RAND_ARRAY(fanotify_init_flags);
}


static unsigned long fanotify_event_flags_base[] = {
	O_RDONLY, O_WRONLY, O_RDWR,
};

static unsigned long fanotify_event_flags_extra[] = {
	O_LARGEFILE, O_CLOEXEC, O_APPEND, O_DSYNC,
	O_NOATIME, O_NONBLOCK, O_SYNC,
};

unsigned long get_fanotify_init_event_flags(void)
{
	unsigned long flags;

	flags = RAND_ARRAY(fanotify_event_flags_base);
	flags |= set_rand_bitmask(ARRAY_SIZE(fanotify_event_flags_extra), fanotify_event_flags_extra);

	return flags;
}

static void sanitise_fanotify_init(struct syscallrecord *rec)
{
	rec->a2 = get_fanotify_init_event_flags();
}

static void post_fanotify_init(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if ((long)rec->retval < 0)
		return;

	new = alloc_object();
	new->fanotifyobj.fd = fd;
	new->fanotifyobj.flags = rec->a1;
	new->fanotifyobj.eventflags = rec->a2;
	add_object(new, OBJ_LOCAL, OBJ_FD_FANOTIFY);
}

struct syscallentry syscall_fanotify_init = {
	.name = "fanotify_init",
	.num_args = 2,
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags", [1] = "event_f_flags" },
	.arg_params[0].list = ARGLIST(fanotify_init_flags),
	.rettype = RET_FD,
	.sanitise = sanitise_fanotify_init,
	.post = post_fanotify_init,
	.group = GROUP_VFS,
};
