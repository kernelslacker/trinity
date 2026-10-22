/*
 * SYSCALL_DEFINE3(sigsuspend, int, unused1, int, unused2, old_sigset_t, mask)
 */
#include "sanitise.h"

struct syscallentry syscall_sigsuspend = {
	.name = "sigsuspend",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argname = { [0] = "unused1", [1] = "unused2", [2] = "mask" },
	.flags = AVOID_SYSCALL | NEED_ALARM, // Confuses the signal state and causes the fuzzer to hang with timeout not firing
	.rettype = RET_BORING,
};
