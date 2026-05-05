/*
 * SYSCALL_DEFINE0(pause)
 */
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * sys_pause has no success path: it sleeps in TASK_INTERRUPTIBLE until a
 * signal whose handler runs is delivered, then returns -ERESTARTNOHAND.
 * The syscall return path translates that into errno=EINTR with retval -1
 * at the userspace boundary, so the only legitimate retval is -1UL.
 * Anything else is a structural ABI violation: a sign-extension or
 * 32-on-64 compat tear in the syscall return path, or a sibling thread
 * scribbling the return slot between syscall return and post-hook entry.
 */
static void post_pause(struct syscallrecord *rec)
{
	unsigned long retval = (unsigned long) rec->retval;

	if (retval != -1UL) {
		outputerr("post_pause: rejected retval 0x%lx (must be -1UL/EINTR)\n",
		          retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_pause = {
	.name = "pause",
	.num_args = 0,
	.flags = AVOID_SYSCALL, // Boring.  Can cause long sleeps
	.group = GROUP_PROCESS,
	.post = post_pause,
};
