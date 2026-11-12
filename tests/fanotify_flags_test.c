/*
 * Self-check for get_fanotify_init_flags() (syscalls/fsnotify/
 * fanotify_init.c), the flags the fanotify provider makes its groups
 * with.  A root run's parent makes the global groups, which every child
 * inherits and could not make itself, so none may be of a content class
 * or have an unlimited queue or mark count.  An unprivileged caller, a
 * child topping up or a non-root run's parent, draws only a group
 * fanotify_init() lets it make.
 */

#include <linux/fanotify.h>
#include <stdbool.h>

#include "debug.h"		/* BUG */
#include "fanotify.h"		/* get_fanotify_init_flags */

#define ROUNDS	1024

/* fanotify_init()'s FANOTIFY_ADMIN_INIT_FLAGS. */
#define ADMIN_FLAGS	(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT | \
			 FAN_REPORT_TID | FAN_REPORT_PIDFD | \
			 FAN_REPORT_FD_ERROR | FAN_UNLIMITED_QUEUE | \
			 FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT)
#define FID_BITS	(FAN_REPORT_FID | FAN_REPORT_DIR_FID | \
			 FAN_REPORT_NAME | FAN_REPORT_TARGET_FID)

/* What fanotify_init() refuses an unprivileged caller, or anyone: the
 * admin flags, a group that reports neither file handles nor mounts, a
 * name without the dir fid, a target fid without the name and the fid,
 * and mount events beside file handles. */
static bool refused_unprivileged(unsigned long flags)
{
	if (flags & ADMIN_FLAGS)
		return true;
	if (!(flags & (FID_BITS | FAN_REPORT_MNT)))
		return true;
	if ((flags & FAN_REPORT_NAME) && !(flags & FAN_REPORT_DIR_FID))
		return true;
	if ((flags & FAN_REPORT_TARGET_FID) &&
	    (!(flags & FAN_REPORT_NAME) || !(flags & FAN_REPORT_FID)))
		return true;
	return (flags & FAN_REPORT_MNT) && (flags & FID_BITS);
}

void fanotify_flags_self_check(void);
void fanotify_flags_self_check(void)
{
	unsigned int i;

	for (i = 0; i < ROUNDS; i++) {
		if (get_fanotify_init_flags(true) &
		    (FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT |
		     FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS))
			BUG("fanotify: the provider drew a content class or an unlimited group");
		if (refused_unprivileged(get_fanotify_init_flags(false)))
			BUG("fanotify: an unprivileged draw is a group the kernel refuses it");
	}
}
