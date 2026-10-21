/*
 * Self-check for the rotation-events sink fd, which the parent opens
 * and every child keeps, so a fuzzed syscall on its number would tear
 * the one file they all append to.  Runs the real
 * stats_rotation_event_*() entry points against the protected-fd
 * registry; the stderr memfd and taint fd are stubbed as not open.
 */

#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "fd.h"
#include "params.h"		/* show_stats */
#include "pids.h"		/* cached_pid */
#include "rotation_event.h"
#include "signals.h"		/* trinity_stderr_memfd */
#include "taint.h"		/* trinity_tainted_fd_cached */

/* Owned by main/params/state.c and dispatch/pids.c in production. */
bool show_stats;
pid_t cached_pid;

/* Live only in a running fuzzer: the registry sees them as not open. */
int trinity_stderr_memfd(void)
{
	return -1;
}

int trinity_tainted_fd_cached(void)
{
	return -1;
}

void fd_protected_self_check(void);
void fd_protected_self_check(void)
{
	char dir[] = "/tmp/trinity-fd-protected-test.XXXXXX";
	char cwd[PATH_MAX];
	glob_t sinkfiles;
	int sink, other;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		BUG("fd protected: getcwd failed");
	if (mkdtemp(dir) == NULL)
		BUG("fd protected: mkdtemp failed");
	/* The sink lands in the launch CWD; keep it out of the tree. */
	if (chdir(dir) != 0)
		BUG("fd protected: cannot enter the scratch directory");

	cached_pid = getpid();
	show_stats = true;
	stats_rotation_event_open();
	show_stats = false;
	sink = stats_rotation_event_fd();
	if (sink < 0)
		BUG("fd protected: the rotation sink did not open");

	other = open("/dev/null", O_RDONLY);
	if (other < 0)
		BUG("fd protected: cannot open a second fd");

	if (!fd_is_protected(STDERR_FILENO))
		BUG("fd protected: stderr is not protected");
	if (fd_is_protected(other))
		BUG("fd protected: an unrelated fd counted as protected");
	if (!fd_is_protected(sink))
		BUG("fd protected: the rotation sink fd is not protected");

	/* A close_range walk starting past stderr must stop at the sink. */
	if (lowest_protected_fd_in_range(STDERR_FILENO + 1, UINT_MAX) != sink)
		BUG("fd protected: a range over the sink did not report it");
	if (lowest_protected_fd_in_range(0, UINT_MAX) != STDERR_FILENO)
		BUG("fd protected: the sink displaced a lower protected fd");
	if (lowest_protected_fd_in_range((unsigned int)sink + 1, UINT_MAX) != -1)
		BUG("fd protected: a range above the sink reported a fd");
	if (sink > STDERR_FILENO + 1 &&
	    lowest_protected_fd_in_range(STDERR_FILENO + 1,
					 (unsigned int)sink - 1) != -1)
		BUG("fd protected: a range below the sink reported a fd");

	/* Once closed the number is free to be reused, so it must not
	 * stay protected. */
	stats_rotation_event_close();
	if (fd_is_protected(sink))
		BUG("fd protected: a closed sink fd is still protected");
	close(other);

	if (glob("rotation-events-*.jsonl", 0, NULL, &sinkfiles) != 0 ||
	    sinkfiles.gl_pathc != 1)
		BUG("fd protected: expected exactly one sink file");
	if (unlink(sinkfiles.gl_pathv[0]) != 0)
		BUG("fd protected: cannot remove the sink file");
	globfree(&sinkfiles);

	if (chdir(cwd) != 0 || rmdir(dir) != 0)
		BUG("fd protected: cleanup failed");
}
