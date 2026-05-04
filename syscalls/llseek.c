/*
 * SYSCALL_DEFINE5(llseek, unsigned int, fd, unsigned long, offset_high,
                unsigned long, offset_low, loff_t __user *, result,
                unsigned int, origin)
 */
#include "random.h"
#include "sanitise.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

static unsigned long llseek_origins[] = {
	SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA,
	SEEK_HOLE,
};

static void sanitise_llseek(struct syscallrecord *rec)
{
	rec->a2 = 0;	/* offset_high: keep offset < 4GB */
	rec->a3 = rand64() & 0x7fffffff;	/* offset_low: non-negative */
	avoid_shared_buffer(&rec->a4, sizeof(loff_t));
}

static void post_llseek(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;
	/*
	 * The kernel reports the resulting offset (a non-negative loff_t)
	 * via *result and returns 0 on success. A negative-but-not-(-1)
	 * retval indicates a sign-extension or 32-on-64 compat tear.
	 */
	if (ret < 0)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_llseek = {
	.name = "llseek",
	.num_args = 5,
	.argtype = { [0] = ARG_FD, [3] = ARG_ADDRESS, [4] = ARG_OP },
	.argname = { [0] = "fd", [1] = "offset_high", [2] = "offset_low", [3] = "result", [4] = "origin" },
	.arg_params[4].list = ARGLIST(llseek_origins),
	.sanitise = sanitise_llseek,
	.post = post_llseek,
	.group = GROUP_VFS,
};
