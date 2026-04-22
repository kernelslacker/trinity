/*
 * SYSCALL_DEFINE1(uname, struct old_utsname __user *, name)
 */
#include <sys/utsname.h>
#include "sanitise.h"

static void sanitise_uname(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct utsname));
}

struct syscallentry syscall_uname = {
	.name = "uname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_uname,
	.group = GROUP_PROCESS,
};
