/*
 * Self-check for get_fanotify_init_flags() (syscalls/fsnotify/
 * fanotify_init.c), the flags the fanotify provider makes its groups
 * with.  A root run's parent makes the global groups, which every child
 * inherits and could not make itself, so none may be of a content class
 * or have an unlimited queue or mark count.
 */

#include <linux/fanotify.h>

#include "debug.h"		/* BUG */
#include "fanotify.h"		/* get_fanotify_init_flags */

#define ROUNDS	1024

void fanotify_flags_self_check(void);
void fanotify_flags_self_check(void)
{
	unsigned int i;

	for (i = 0; i < ROUNDS; i++) {
		if (get_fanotify_init_flags() &
		    (FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT |
		     FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS))
			BUG("fanotify: the provider drew a content class or an unlimited group");
	}
}
