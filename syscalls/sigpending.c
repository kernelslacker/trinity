/*
 * SYSCALL_DEFINE1(sigpending, old_sigset_t __user *, set)
 */
#include <signal.h>
#include "sanitise.h"

static void sanitise_sigpending(struct syscallrecord *rec)
{
	/*
	 * Legacy sigpending takes a single old_sigset_t (one word) writeback
	 * target.  rt_sigpending was scrubbed in the prior batch using its
	 * caller-supplied a2 length; sigpending has no length arg, so use
	 * sigset_t as the conservative upper bound.
	 */
	avoid_shared_buffer(&rec->a1, sizeof(sigset_t));
}

struct syscallentry syscall_sigpending = {
	.name = "sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "set" },
	.sanitise = sanitise_sigpending,
};
