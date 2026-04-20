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

	if ((long)rec->retval < 0)
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
	.argtype = { [0] = ARG_OP, [1] = ARG_LIST },
	.argname = { [0] = "clockid", [1] = "flags" },
	.arg_params[0].list = ARGLIST(timerfd_create_clockids),
	.arg_params[1].list = ARGLIST(timerfd_create_flags),
	.rettype = RET_FD,
	.ret_objtype = OBJ_FD_TIMERFD,
	.post = post_timerfd_create,
};
