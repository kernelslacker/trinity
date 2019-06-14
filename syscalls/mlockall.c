/*
 * SYSCALL_DEFINE1(mlockall, int, flags)
 */
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"

#ifndef MCL_CURRENT
#define MCL_CURRENT     1
#endif
#ifndef MCL_FUTURE
#define MCL_FUTURE      2
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT	4
#endif

static unsigned long mlockall_flags[] = {
	MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT,
};

struct syscallentry syscall_mlockall = {
	.name = "mlockall",
	.num_args = 1,
	.arg1name = "flags",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(mlockall_flags),
	.group = GROUP_VM,
};
