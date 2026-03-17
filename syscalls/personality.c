/*
 * SYSCALL_DEFINE1(personality, unsigned int, personality
 */
#include "sanitise.h"

struct syscallentry syscall_personality = {
	.name = "personality",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.arg1name = "personality",
};
