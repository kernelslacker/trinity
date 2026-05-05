/*
 * SYSCALL_DEFINE1(nice, int, increment)
 */
#include "random.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_nice(struct syscallrecord *rec)
{
	rec->a1 = (unsigned long)((rand() % 40) - 20);	/* -20 to 19 */
}

/*
 * sys_nice clamps the new nice value to [MIN_NICE, MAX_NICE] = [-20, 19]
 * before applying it, then returns 0 on success or a negative errno on
 * failure (-EPERM from can_nice(), or whatever security_task_setnice()
 * yields). The userspace syscall return path collapses any negative
 * errno to retval=-1UL with errno set, so the only legitimate retvals
 * are 0 and -1UL -- both of which fall inside the structural envelope
 * [-20, 19] U {-1UL}. A retval strictly outside that range is a
 * sign-extension at the syscall ABI boundary, a 32-on-64 compat tear,
 * or a sibling thread scribbling the return slot between syscall return
 * and post-hook entry.
 */
static void post_nice(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if ((unsigned long) rec->retval == -1UL)
		return;
	if (ret < -20 || ret > 19) {
		outputerr("post_nice: rejected retval 0x%lx outside [-20, 19] (and not -1)\n",
		          (unsigned long) rec->retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_nice = {
	.name = "nice",
	.num_args = 1,
	.argname = { [0] = "increment" },
	.sanitise = sanitise_nice,
	.post = post_nice,
	.group = GROUP_SCHED,
};
