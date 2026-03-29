/*
 * SYSCALL_DEFINE6(pselect6, int, n, fd_set __user *, inp, fd_set __user *, outp,
	fd_set __user *, exp, struct timespec __user *, tsp,
	void __user *, sig)
 */
#include "sanitise.h"

struct syscallentry syscall_pselect6 = {
	.name = "pselect6",
	.num_args = 6,
	.flags = AVOID_SYSCALL, // Can cause the fuzzer to hang without timeout firing
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_ADDRESS, [4] = ARG_ADDRESS, [5] = ARG_ADDRESS },
	.argname = { [0] = "n", [1] = "inp", [2] = "outp", [3] = "exp", [4] = "tsp", [5] = "sig" },
	.group = GROUP_VFS,
};
