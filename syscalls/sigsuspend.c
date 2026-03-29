/*
 * asmlinkage int
   sys_sigsuspend(int history0, int history1, old_sigset_t mask)
 */
#include "sanitise.h"

struct syscallentry syscall_sigsuspend = {
	.name = "sigsuspend",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argname = { [0] = "history0", [1] = "history1", [2] = "mask" },
	.flags = AVOID_SYSCALL, // Confuses the signal state and causes the fuzzer to hang with timeout not firing
};
