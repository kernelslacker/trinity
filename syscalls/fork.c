/*
   int sys_fork(struct pt_regs *regs)
 */
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include "pids.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/*
 * Because we don't want to forkbomb, we don't really do anything in the child process.
 * We only actually do a fork at all on the off-chance that it might trigger some oddness
 * in the VMAs we've created when we COW.
 *
 * TODO: Maybe do some dirty_mapping calls in the child ?
 * TODO: Maybe we could enforce an upper limit on the child count before we fork,
 *        and keep track of them using handle_child ?
 */

static void post_fork(struct syscallrecord *rec)
{
	pid_t pid;

	pid = rec->retval;
	if (pid == 0) {
		// child
		sleep(1);
		_exit(EXIT_SUCCESS);
	} else {
		__unused__ int ret;

		while (pid_alive(pid) == TRUE) {
			int status;
			ret = waitpid(pid, &status, WUNTRACED | WCONTINUED | WNOHANG);
		}
	}
}

struct syscallentry syscall_fork = {
	.name = "fork",
	.num_args = 0,
	.flags = AVOID_SYSCALL, // No args to fuzz, confuses fuzzer
	.post = post_fork,
};
