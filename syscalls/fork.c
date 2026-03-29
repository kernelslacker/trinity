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

/*
 * Pre-fork capacity check.  If we're already at the child limit,
 * flag rec->a1 so the forked child exits immediately without
 * doing any COW dirty work.  fork() has no arguments, so a1 is
 * unused by the kernel and safe to repurpose as a flag.
 */
static void sanitise_fork(struct syscallrecord *rec)
{
	if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) >= max_children)
		rec->a1 = 1;
	else
		rec->a1 = 0;
}

static void post_fork(struct syscallrecord *rec)
{
	pid_t pid;

	pid = rec->retval;
	if (pid == 0) {
		/* Flagged at capacity by sanitise, or over limit now — bail. */
		if (rec->a1 || __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) >= max_children)
			_exit(EXIT_SUCCESS);

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
	.sanitise = sanitise_fork,
	.post = post_fork,
};
