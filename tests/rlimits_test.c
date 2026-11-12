/*
 * Self-check for init_rlimits() (utils/rlimits.c): the NOFILE limit the
 * spawn headroom check reads afterwards is the one it capped, not the one
 * init_main_process() read before it.  A forked child, since the caps are
 * the process's own, raises its soft NOFILE above the cap and runs
 * init_rlimits() on that.
 */

#include <stdio.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "rlimits.h"		/* init_rlimits */
#include "trinity.h"		/* max_files_rlimit */
#include "utils.h"		/* waitpid_eintr */

/* utils/rlimits.c's NOFILE_TARGET. */
#define NOFILE_CAP	262144UL

/* Exit codes of the child. */
#define CAPPED		0
#define STALE		1
#define NO_SETUP	2
#define NO_ROOM		3	/* the hard limit leaves nothing to cap */

static void __attribute__((noreturn)) cap_in_child(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
		_exit(NO_SETUP);
	if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max <= NOFILE_CAP)
		_exit(NO_ROOM);
	rl.rlim_cur = rl.rlim_max == RLIM_INFINITY ? 2 * NOFILE_CAP : rl.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
		_exit(NO_SETUP);
	max_files_rlimit = rl;	/* what init_main_process() reads */

	init_rlimits(1);
	_exit(max_files_rlimit.rlim_cur == NOFILE_CAP ? CAPPED : STALE);
}

void rlimits_self_check(void);
void rlimits_self_check(void)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		BUG("rlimits: fork failed");
	if (pid == 0)
		cap_in_child();

	if (waitpid_eintr(pid, &status, 0) != pid || !WIFEXITED(status))
		BUG("rlimits: the child did not exit");
	switch (WEXITSTATUS(status)) {
	case CAPPED:
		break;
	case NO_ROOM:
		printf("(NOFILE hard limit at or under the cap, skipping) ");
		break;
	case STALE:
		BUG("rlimits: the NOFILE limit read back is not the capped one");
	default:
		BUG("rlimits: the child could not raise its NOFILE limit");
	}
}
