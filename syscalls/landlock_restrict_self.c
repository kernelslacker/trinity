/*
 * SYSCALL_DEFINE2(landlock_restrict_self,
 *                const int, ruleset_fd, const __u32, flags)
 */
#include "sanitise.h"

static void sanitise_landlock_restrict_self(struct syscallrecord *rec)
{
	rec->a2 = 0;	/* flags: MBZ */
}

struct syscallentry syscall_landlock_restrict_self = {
	.name = "landlock_restrict_self",
	.num_args = 2,
	.argtype = { [0] = ARG_FD_LANDLOCK },
	.argname = { [0] = "fd", [1] = "flags" },
	.sanitise = sanitise_landlock_restrict_self,
	.group = GROUP_PROCESS,
};
