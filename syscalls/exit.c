/*
 * SYSCALL_DEFINE1(exit, int, error_code)
 */
#include "sanitise.h"

struct syscallentry syscall_exit = {
	.name = "exit",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.flags = AVOID_SYSCALL | AVOID_REEXEC, // confuses fuzzer; AVOID_REEXEC is belt-and-braces against the redqueen tail
	.argname = { [0] = "error_code" },
};
