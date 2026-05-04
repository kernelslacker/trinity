/*
 * SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr)
 */
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void post_set_tid_address(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	/*
	 * Kernel ABI: set_tid_address returns current->pid, which is a valid
	 * tid in [1, PID_MAX_LIMIT=4194304], or -1UL on failure. A retval
	 * outside that range (and not -1UL) is a structural ABI regression
	 * in the syscall return path, not just a value mismatch.
	 */
	if (ret == -1L)
		return;

	if (ret < 1 || ret > 4194304)
		post_handler_corrupt_ptr_bump(rec, NULL);
}

struct syscallentry syscall_set_tid_address = {
	.name = "set_tid_address",
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "tidptr" },
	.flags = AVOID_SYSCALL,
	.group = GROUP_PROCESS,
	.post = post_set_tid_address,
};
