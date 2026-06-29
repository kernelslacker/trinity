/*
 * SYSCALL_DEFINE1(brk, unsigned long, brk)
 *
 * On success: Returns the new program break
 * On failure: Returns current program break
 */
#include "sanitise.h"

struct syscallentry syscall_brk = {
	.name = "brk",
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "brk" },
	/*
	 * sys_brk returns the new program break (or the current break on
	 * failure), NOT 0 on success.  AVOID_SYSCALL keeps trinity from
	 * actually dispatching brk in practice, so the misclassification
	 * has been latent, but the gate would mis-reject every legitimate
	 * brk-style return if the flag is ever lifted.  RET_BORING matches
	 * what brk-shape syscalls (sbrk, mmap-derived address returns)
	 * use elsewhere.
	 */
	.rettype = RET_BORING,
	.flags = AVOID_SYSCALL,
	.group = GROUP_VM,
};
