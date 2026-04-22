/*
 * SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
 */
#include <sys/sysinfo.h>
#include "sanitise.h"

static void sanitise_sysinfo(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct sysinfo));
}

struct syscallentry syscall_sysinfo = {
	.name = "sysinfo",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "info" },
	.sanitise = sanitise_sysinfo,
	.group = GROUP_PROCESS,
};
