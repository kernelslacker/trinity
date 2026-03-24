/*
 * SYSCALL_DEFINE5(llseek, unsigned int, fd, unsigned long, offset_high,
                unsigned long, offset_low, loff_t __user *, result,
                unsigned int, origin)
 */
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static unsigned long llseek_origins[] = {
	SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA,
	SEEK_HOLE,
};

static void sanitise_llseek(struct syscallrecord *rec)
{
	rec->a2 = 0;	/* offset_high: keep offset < 4GB */
	rec->a3 = rand64() & 0x7fffffff;	/* offset_low: non-negative */
}

struct syscallentry syscall_llseek = {
	.name = "llseek",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "offset_high",
	.arg3name = "offset_low",
	.arg4name = "result",
	.arg4type = ARG_ADDRESS,
	.arg5name = "origin",
	.arg5type = ARG_OP,
	.arg5list = ARGLIST(llseek_origins),
	.sanitise = sanitise_llseek,
	.group = GROUP_VFS,
};
