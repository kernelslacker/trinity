/*
   int sys_fork(struct pt_regs *regs)
 */
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include "maps.h"
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

/*
 * Because we don't want to forkbomb, we don't really do anything in the child process.
 * We only actually do a fork at all on the off-chance that it might trigger some oddness
 * in the VMAs we've created when we COW.
 */

static void post_fork(struct syscallrecord *rec)
{
	pid_t pid;

	pid = rec->retval;
	if (pid == 0) {
		/* If we're already at capacity, bail out immediately. */
		if (shm->running_childs >= max_children) {
			_exit(EXIT_SUCCESS);
		}

		/* Dirty a couple of random mappings to exercise COW paths. */
		dirty_random_mapping();
		if (RAND_BOOL())
			dirty_random_mapping();

		_exit(EXIT_SUCCESS);
	} else {
		__unused__ int ret;

		while (pid_alive(pid) == true) {
			int status;
			ret = waitpid(pid, &status, WUNTRACED | WCONTINUED | WNOHANG);
		}
	}
}

struct syscallentry syscall_fork = {
	.name = "fork",
	.group = GROUP_PROCESS,
	.num_args = 0,
	.flags = AVOID_SYSCALL, // No args to fuzz, confuses fuzzer
	.post = post_fork,
};
