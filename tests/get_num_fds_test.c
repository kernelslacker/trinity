/*
 * Self-check for get_num_fds() (utils/utils.c), the parent's count of
 * its own open fds that spawn_child() weighs against RLIMIT_NOFILE
 * before every fork.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "pids.h"		/* mainpid */
#include "utils.h"		/* get_num_fds, waitpid_eintr */

#define NR_EXTRA	3

/* The count follows the fds the process holds: it sees fds opened and
 * closed.  The directory handle it opens to count with is in every
 * count, so only differences mean anything. */
static void count_follows_open_fds(void)
{
	int fds[NR_EXTRA];
	int base = get_num_fds();
	unsigned int i;

	if (base < 1)
		BUG("get_num_fds: did not count even its own directory handle");

	for (i = 0; i < NR_EXTRA; i++) {
		fds[i] = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fds[i] < 0)
			BUG("get_num_fds: cannot open /dev/null");
	}
	if (get_num_fds() != base + NR_EXTRA)
		BUG("get_num_fds: did not see the fds opened");

	for (i = 0; i < NR_EXTRA; i++)
		close(fds[i]);
	if (get_num_fds() != base)
		BUG("get_num_fds: did not see the fds closed");
}

/* How the helper below ended. */
enum {
	HELPER_OK,
	HELPER_NO_SETUP,
	HELPER_COUNTED,		/* the count did not fail */
	HELPER_NO_ERRNO,	/* it failed, but not with EMFILE */
};

/* A parent that is out of fds cannot open /proc/<pid>/fd to count
 * them, and the count has to say so: a 0 would pass spawn_child()'s
 * headroom check just when there is none.  RLIMIT_NOFILE is cut to the
 * first free fd number in a task of its own, so its next open() fails. */
static void failed_count_is_reported(void)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("get_num_fds: fork failed");
	if (pid == 0) {
		struct rlimit rl;
		int fd, count;

		/* The count reads /proc/<mainpid>/fd, the parent's own. */
		mainpid = getpid();
		fd = open("/dev/null", O_RDONLY);
		if (fd < 0 || getrlimit(RLIMIT_NOFILE, &rl) != 0)
			_exit(HELPER_NO_SETUP);
		close(fd);
		rl.rlim_cur = fd;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			_exit(HELPER_NO_SETUP);

		errno = 0;
		count = get_num_fds();
		if (count != -1)
			_exit(HELPER_COUNTED);
		_exit(errno == EMFILE ? HELPER_OK : HELPER_NO_ERRNO);
	}
	if (waitpid_eintr(pid, &status, 0) != pid || !WIFEXITED(status))
		BUG("get_num_fds: the fd limit helper did not exit");

	switch (WEXITSTATUS(status)) {
	case HELPER_OK:
		return;
	case HELPER_NO_SETUP:
		BUG("get_num_fds: cannot lower RLIMIT_NOFILE in the helper");
	case HELPER_COUNTED:
		BUG("get_num_fds: an exhausted fd table did not fail the count");
	default:
		BUG("get_num_fds: the failed count did not keep EMFILE");
	}
}

void get_num_fds_self_check(void);
void get_num_fds_self_check(void)
{
	count_follows_open_fds();
	failed_count_is_reported();
}
