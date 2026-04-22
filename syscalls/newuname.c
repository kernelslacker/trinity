/*
 *
 * SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
 */
#include <sys/utsname.h>
#include "sanitise.h"

static void sanitise_newuname(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct utsname));
}

struct syscallentry syscall_newuname = {
	.name = "newuname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_newuname,
	.group = GROUP_PROCESS,
};
