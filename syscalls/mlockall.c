/*
 * SYSCALL_DEFINE1(mlockall, int, flags)
 */
#include <stdlib.h>
#include "random.h"
#include "sanitise.h"
#include "shm.h"
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
	.argtype = { [0] = ARG_LIST },
	.argname = { [0] = "flags" },
	.arg_params[0].list = ARGLIST(mlockall_flags),
	.group = GROUP_VM,
};
