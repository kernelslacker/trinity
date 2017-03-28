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

#include <fcntl.h>
#include "fanotify.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

static unsigned long fanotify_init_flags[] = {
	FAN_CLOEXEC , FAN_NONBLOCK, FAN_UNLIMITED_QUEUE , FAN_UNLIMITED_MARKS,
	FAN_CLASS_NOTIF, FAN_CLASS_CONTENT, FAN_CLASS_PRE_CONTENT,
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

struct syscallentry syscall_fanotify_init = {
	.name = "fanotify_init",
	.num_args = 2,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(fanotify_init_flags),
	.arg2name = "event_f_flags",
	.rettype = RET_FD,
	.sanitise = sanitise_fanotify_init,
	.group = GROUP_VFS,
};
