/*
 * SYSCALL_DEFINE1(personality, unsigned int, personality
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_personality = {
	.name = "personality",
	.num_args = 1,
	.arg1name = "personality",
};
