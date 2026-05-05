/*
 * SYSCALL_DEFINE2(landlock_restrict_self,
 *                const int, ruleset_fd, const __u32, flags)
 */
#include <linux/landlock.h>
#include "random.h"
#include "sanitise.h"

#ifndef LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF	(1U << 0)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON		(1U << 1)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF
#define LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF	(1U << 2)
#endif
#ifndef LANDLOCK_RESTRICT_SELF_TSYNC
#define LANDLOCK_RESTRICT_SELF_TSYNC			(1U << 3)
#endif

static unsigned long landlock_restrict_self_flags[] = {
	0,
	LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF,
	LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,
	LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF,
	LANDLOCK_RESTRICT_SELF_TSYNC,
};

static void sanitise_landlock_restrict_self(struct syscallrecord *rec)
{
	rec->a2 = landlock_restrict_self_flags[rand() % ARRAY_SIZE(landlock_restrict_self_flags)];
}

struct syscallentry syscall_landlock_restrict_self = {
	.name = "landlock_restrict_self",
	.num_args = 2,
	.argtype = { [0] = ARG_FD_LANDLOCK },
	.argname = { [0] = "fd", [1] = "flags" },
	.sanitise = sanitise_landlock_restrict_self,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};
