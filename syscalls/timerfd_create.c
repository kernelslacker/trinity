/*
 * SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
 */
#include <time.h>
#include "objects.h"
#include "sanitise.h"
#include "compat.h"

static unsigned long timerfd_create_clockids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
};

static unsigned long timerfd_create_flags[] = {
	TFD_NONBLOCK, TFD_CLOEXEC,
};

static void post_timerfd_create(struct syscallrecord *rec)
{
	struct object *new;
	int fd = rec->retval;

	if (fd == -1)
		return;

	new = alloc_object();
	new->timerfdobj.fd = fd;
	new->timerfdobj.clockid = rec->a1;
	new->timerfdobj.flags = rec->a2;
	add_object(new, OBJ_LOCAL, OBJ_FD_TIMERFD);
}

struct syscallentry syscall_timerfd_create = {
	.name = "timerfd_create",
	.group = GROUP_TIME,
	.num_args = 2,
	.arg1name = "clockid",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(timerfd_create_clockids),
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(timerfd_create_flags),
	.rettype = RET_FD,
	.post = post_timerfd_create,
};
