/*
 * SYSCALL_DEFINE1(personality, unsigned int, personality
 */
#include <stdint.h>
#include <sys/personality.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static unsigned long personalities[] = {
	PER_LINUX, PER_SVR4, PER_SVR3, PER_SCOSVR3,
	PER_OSR5, PER_WYSEV386, PER_ISCR4, PER_BSD,
	PER_LINUX32,
};

static void post_personality(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	/* Reject retval with high bits set — personality value is 32-bit unsigned. */
	if ((unsigned long) ret > (unsigned long) UINT32_MAX) {
		output(0, "post_personality: rejected retval 0x%lx outside [0, UINT32_MAX]\n",
		       (unsigned long) ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_personality = {
	.name = "personality",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "personality" },
	.arg_params[0].list = ARGLIST(personalities),
	.post = post_personality,
};
