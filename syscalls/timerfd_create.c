/*
 * SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
 */
#include <time.h>
#include "sanitise.h"
#include "compat.h"

static unsigned long timerfd_create_clockids[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC,
};

static unsigned long timerfd_create_flags[] = {
	TFD_NONBLOCK, TFD_CLOEXEC,
};

struct syscallentry syscall_timerfd_create = {
	.name = "timerfd_create",
	.num_args = 2,
	.arg1name = "clockid",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(timerfd_create_clockids),
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(timerfd_create_flags),
};
