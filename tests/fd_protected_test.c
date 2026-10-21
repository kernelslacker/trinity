/*
 * Self-check for the rotation-events sink fd, which the parent opens
 * and every child keeps: a fuzzed syscall on its number would tear the
 * one file they all append to, and an exec'd image must not inherit it.
 * Runs the real stats_rotation_event_*() entry points against the
 * protected-fd registry; its other inputs (stderr memfd, taint fd) are
 * stubbed as not open.
 */

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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

/* The registry must name @sink for single-fd and for range queries, and
 * keep its verdict on stderr and on the unrelated fd @other. */
static void check_registry(int sink, int other)
{
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
}

void fd_protected_self_check(void);
void fd_protected_self_check(void)
{
	char dir[] = "/tmp/trinity-fd-protected-test.XXXXXX";
	char cwd[PATH_MAX];
	char line[64];
	struct rlimit orig, lim;
	glob_t sinkfiles;
	FILE *f;
	bool can_park;
	int sink, moved, other;

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
	/* The descriptor the parent opens is judged here; the child's move
	 * makes its own. */
	if (!(fcntl(sink, F_GETFD) & FD_CLOEXEC))
		BUG("fd protected: the sink is not close-on-exec at open");
	/* The parent keeps the number it opened: it fuzzes nothing, and a
	 * high fd there would make every fork copy a 60k-slot fd table. */
	if ((unsigned int)sink >= ROTATION_EVENT_FD_HIGH_BASE)
		BUG("fd protected: the parent moved the sink above the picker range");

	other = open("/dev/null", O_RDONLY);
	if (other < 0)
		BUG("fd protected: cannot open a second fd");

	/* With the soft RLIMIT_NOFILE at the base, F_DUPFD cannot reach a
	 * slot there.  The child keeps the number it inherited, and the
	 * registry still has to name it. */
	if (getrlimit(RLIMIT_NOFILE, &orig) != 0)
		BUG("fd protected: getrlimit failed");
	lim = orig;
	if (lim.rlim_cur == RLIM_INFINITY ||
	    lim.rlim_cur > ROTATION_EVENT_FD_HIGH_BASE)
		lim.rlim_cur = ROTATION_EVENT_FD_HIGH_BASE;
	if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
		BUG("fd protected: cannot lower RLIMIT_NOFILE");
	stats_rotation_event_relocate_in_child();
	if (stats_rotation_event_fd() != sink)
		BUG("fd protected: a failed move changed the sink fd");
	if (fcntl(sink, F_GETFD) == -1)
		BUG("fd protected: a failed move closed the sink");
	check_registry(sink, other);

	/* Moving the sink up needs a soft limit above the base, and a login
	 * shell's 1024 is not.  Ask for as much as the hard limit allows. */
	lim = orig;
	if (lim.rlim_cur != RLIM_INFINITY &&
	    lim.rlim_cur <= ROTATION_EVENT_FD_HIGH_BASE)
		lim.rlim_cur = lim.rlim_max < 65536 ? lim.rlim_max : 65536;
	can_park = lim.rlim_cur == RLIM_INFINITY ||
		   lim.rlim_cur > ROTATION_EVENT_FD_HIGH_BASE;

	moved = sink;
	if (!can_park) {
		fprintf(stderr, "fd protected: RLIMIT_NOFILE hard limit %lu is "
			"not above %u, sink relocation not checked\n",
			(unsigned long)orig.rlim_max,
			ROTATION_EVENT_FD_HIGH_BASE);
	} else {
		if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
			BUG("fd protected: cannot raise RLIMIT_NOFILE");
		stats_rotation_event_relocate_in_child();
		moved = stats_rotation_event_fd();

		if ((unsigned int)moved < ROTATION_EVENT_FD_HIGH_BASE)
			BUG("fd protected: a child did not move the sink above the picker range");
		/* The inherited number is free for the child to reuse. */
		if (fcntl(sink, F_GETFD) != -1 || errno != EBADF)
			BUG("fd protected: the inherited low number is still open");
		/* A fuzzed execve in a grandchild must not inherit the sink. */
		if (!(fcntl(moved, F_GETFD) & FD_CLOEXEC))
			BUG("fd protected: the moved sink is not close-on-exec");
		check_registry(moved, other);
	}
	if (setrlimit(RLIMIT_NOFILE, &orig) != 0)
		BUG("fd protected: cannot restore RLIMIT_NOFILE");

	/* Once closed the number is free to be reused, so it must not
	 * stay protected. */
	stats_rotation_event_close();
	if (fd_is_protected(moved))
		BUG("fd protected: a closed sink fd is still protected");
	close(other);

	if (glob("rotation-events-*.jsonl", 0, NULL, &sinkfiles) != 0 ||
	    sinkfiles.gl_pathc != 1)
		BUG("fd protected: expected exactly one sink file");
	/* The close above writes the terminal record through whichever fd
	 * the sink ended up on; a whole line must land in the file the open
	 * created.  Its shape is pinned by stats-rotation-jsonl-schema. */
	f = fopen(sinkfiles.gl_pathv[0], "r");
	if (f == NULL || fgets(line, sizeof(line), f) == NULL ||
	    line[strlen(line) - 1] != '\n')
		BUG("fd protected: the sink file has no complete record");
	fclose(f);
	if (unlink(sinkfiles.gl_pathv[0]) != 0)
		BUG("fd protected: cannot remove the sink file");
	globfree(&sinkfiles);

	if (chdir(cwd) != 0 || rmdir(dir) != 0)
		BUG("fd protected: cleanup failed");
}
