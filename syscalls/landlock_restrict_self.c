/*
 * SYSCALL_DEFINE2(landlock_restrict_self,
 *                const int, ruleset_fd, const __u32, flags)
 */
#include "sanitise.h"

//static unsigned long landlock_restrict_self_flags[] = {
//	,
//};

struct syscallentry syscall_landlock_restrict_self = {
	.name = "landlock_restrict_self",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "flags",
//	arg2type = ARG_LIST,
//	arg2list = ARGLIST(landlock_restrict_self_flags),
};
