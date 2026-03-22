/*
 * SYSCALL_DEFINE1(personality, unsigned int, personality
 */
#include <sys/personality.h>
#include "sanitise.h"

static unsigned long personalities[] = {
	PER_LINUX, PER_SVR4, PER_SVR3, PER_SCOSVR3,
	PER_OSR5, PER_WYSEV386, PER_ISCR4, PER_BSD,
	PER_LINUX32,
};

struct syscallentry syscall_personality = {
	.name = "personality",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.arg1name = "personality",
	.arg1type = ARG_OP,
	.arg1list = ARGLIST(personalities),
};
