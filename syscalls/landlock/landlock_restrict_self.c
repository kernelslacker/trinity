/*
 * SYSCALL_DEFINE2(landlock_restrict_self,
 *                const int, ruleset_fd, const __u32, flags)
 */
#include <linux/landlock.h>
#include "random.h"
#include "rnd.h"
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
#ifndef LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS
#define LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS		(1U << 4)
#endif

/*
 * Index 0 is reserved as 0 (no flags); indices 1..N hold individual legal
 * flags iterated below to produce OR-based multi-flag combinations.
 */
static const unsigned long landlock_restrict_self_flags[] = {
	0,
	LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF,
	LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,
	LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF,
	LANDLOCK_RESTRICT_SELF_TSYNC,
	LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS,
};

static void sanitise_landlock_restrict_self(struct syscallrecord *rec)
{
	unsigned long flags = 0;
	unsigned int i;

	/* Zero flags: tests the no-restriction baseline. */
	if (ONE_IN(8)) {
		rec->a2 = 0;
		return;
	}
	/* Undefined bits: exercises the -EINVAL reject path. */
	if (ONE_IN(8)) {
		rec->a2 = ONE_IN(2) ? (1U << 5) : 0xffffffff;
		return;
	}
	/* OR a random subset so multi-flag combinations are reachable. */
	for (i = 1; i < ARRAY_SIZE(landlock_restrict_self_flags); i++) {
		if (RAND_BOOL())
			flags |= landlock_restrict_self_flags[i];
	}
	rec->a2 = flags;
}

struct syscallentry syscall_landlock_restrict_self = {
	.name = "landlock_restrict_self",
	.num_args = 2,
	.argtype = { [0] = ARG_FD_LANDLOCK },
	.argname = { [0] = "fd", [1] = "flags" },
	.sanitise = sanitise_landlock_restrict_self,
	.flags = REEXEC_SANITISE_OK,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};
