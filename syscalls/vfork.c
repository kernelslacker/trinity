/*
   int sys_vfork(struct pt_regs *regs)
 */
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "pids.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"		/* waitpid_eintr() */

static void post_vfork(struct syscallrecord *rec)
{
	unsigned long retval = rec->retval;
	pid_t pid = (pid_t) retval;

	if (pid == 0) {
		/*
		 * vfork suspends the parent until the child exits or execs,
		 * and the child shares the parent address space — touching
		 * mappings here would corrupt the parent. Exit immediately.
		 */
		_exit(EXIT_SUCCESS);
	} else {
		__unused__ int ret;

		/*
		 * Kernel ABI: parent retval is the child pid in [1, PID_MAX_LIMIT=4194304],
		 * or -1UL on failure. Anything else is a corrupted retval (sign-extension
		 * tear or pid_ns translation bug) — reject before pid_alive()/waitpid()
		 * steers wait-loop bookkeeping off real children.
		 */
		if (retval > 4194304UL && retval != (unsigned long)-1L) {
			output(0, "post_vfork: rejected returned pid 0x%lx outside [1, PID_MAX_LIMIT=4194304] (and not -1)\n",
			       retval);
			post_handler_corrupt_ptr_bump(rec, NULL);
			return;
		}

		while (pid_alive(pid) == true) {
			int status;
			ret = waitpid_eintr(pid, &status, WUNTRACED | WCONTINUED | WNOHANG);
		}
	}
}

struct syscallentry syscall_vfork = {
	.name = "vfork",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.flags = AVOID_SYSCALL | EXTRA_FORK, // No args, confuses fuzzer
	.argname = { [0] = "regs" },
	.post = post_vfork,
	.rettype = RET_PID_T,
	.ret_objtype = OBJ_PID,
};
