/*
 * SYSCALL_DEFINE1(exit, int, error_code)
 */
#include "sanitise.h"

struct syscallentry syscall_exit = {
	.name = "exit",
	.num_args = 1,
	.flags = AVOID_SYSCALL, // confuses fuzzer
	.arg1name = "error_code",
};
