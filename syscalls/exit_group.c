/*
 * SYSCALL_DEFINE1(exit_group, int, error_code)
 */
#include "sanitise.h"

struct syscallentry syscall_exit_group = {
	.name = "exit_group",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.flags = AVOID_SYSCALL | AVOID_REEXEC, // No args to fuzz, confuses fuzzer; AVOID_REEXEC is belt-and-braces against the redqueen tail
	.argname = { [0] = "error_code" },
};
