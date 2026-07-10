/*
 * SYSCALL_DEFINE1(nice, int, increment)
 */
#include <limits.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_nice(struct syscallrecord *rec)
{
	/*
	 * sys_nice() clamps the new nice value to [MIN_NICE, MAX_NICE] =
	 * [-20, 19] inside the kernel before applying it, so feeding only
	 * the legal range stops exercising the clamp / sign-extension path.
	 * Add a small out-of-range bucket (~10%) that pushes the increment
	 * well outside [-20, 19] -- both directions, including INT_MIN /
	 * INT_MAX adjacent values -- so the clamp arithmetic and the
	 * compat sign-extension stay covered.
	 */
	if (ONE_IN(10)) {
		switch (rnd_modulo_u32(4)) {
		case 0: rec->a1 = (unsigned long)(long) INT_MIN; break;
		case 1: rec->a1 = (unsigned long)(long) INT_MAX; break;
		case 2: rec->a1 = (unsigned long)(long)(-21 -
				(int) rnd_modulo_u32(2048)); break;
		default: rec->a1 = (unsigned long)(long)(20 +
				(int) rnd_modulo_u32(2048)); break;
		}
		return;
	}

	rec->a1 = (unsigned long)((rnd_modulo_u32(40)) - 20);	/* -20 to 19 */
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

	if (ret == -1L)
		return;
	if (ret < -20 || ret > 19) {
		outputerr("post_nice: rejected retval 0x%lx outside [-20, 19] (and not -1)\n",
		          (unsigned long) ret);
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
	.rettype = RET_BORING,
};
