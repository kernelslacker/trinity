/*
 * Self-check for get_num_fds() (utils/utils.c), the parent's count of
 * its own open fds that spawn_child() weighs against RLIMIT_NOFILE
 * before every fork, and for what spawn_child() does when it cannot
 * count them.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "exit.h"
#include "main-internal.h"
#include "pids.h"		/* mainpid */
#include "shm.h"
#include "utils-macros.h"	/* ARRAY_SIZE */
#include "utils.h"		/* get_num_fds, waitpid_eintr */

#include "fake_parent.h"

void __real_replace_child(int childno);

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

/* How a body run with the fd table full ended. */
enum {
	RUN_OK,
	RUN_NO_SETUP,
	RUN_COUNTED,		/* the count did not fail */
	RUN_NO_ERRNO,		/* it failed, but not with EMFILE */
	RUN_FORKED,		/* the spawn went ahead */
	RUN_NOT_STOPPED,	/* the spawn failed, but the run goes on */
	RUN_RETRIED,		/* the spawn was retried or slept on */
};

/* Run @body in a task of its own with RLIMIT_NOFILE cut to the first
 * free fd number, so that its next open() fails with EMFILE, and return
 * how it ended. */
static int run_with_fd_table_full(int (*body)(void))
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("get_num_fds: fork failed");
	if (pid == 0) {
		struct rlimit rl;
		int fd;

		/* The count reads /proc/<mainpid>/fd, the parent's own. */
		mainpid = getpid();
		fd = open("/dev/null", O_RDONLY);
		if (fd < 0 || getrlimit(RLIMIT_NOFILE, &rl) != 0)
			_exit(RUN_NO_SETUP);
		close(fd);
		rl.rlim_cur = fd;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			_exit(RUN_NO_SETUP);

		_exit(body());
	}
	if (waitpid_eintr(pid, &status, 0) != pid || !WIFEXITED(status))
		BUG("get_num_fds: the fd limit helper did not exit");
	if (WEXITSTATUS(status) == RUN_NO_SETUP)
		BUG("get_num_fds: cannot lower RLIMIT_NOFILE in the helper");
	return WEXITSTATUS(status);
}

static int count_with_fd_table_full(void)
{
	errno = 0;
	if (get_num_fds() != -1)
		return RUN_COUNTED;
	return errno == EMFILE ? RUN_OK : RUN_NO_ERRNO;
}

/* A parent that is out of fds cannot open /proc/<pid>/fd to count
 * them, and the count has to say so: a 0 would pass spawn_child()'s
 * headroom check just when there is none. */
static void failed_count_is_reported(void)
{
	switch (run_with_fd_table_full(count_with_fd_table_full)) {
	case RUN_OK:
		return;
	case RUN_COUNTED:
		BUG("get_num_fds: an exhausted fd table did not fail the count");
	default:
		BUG("get_num_fds: the failed count did not keep EMFILE");
	}
}

/* The errno the count is made to fail with.  0 leaves it to the real
 * count, which the fd table helper fails for want of fds. */
static int injected_errno;

static int refill_with_failing_count(void)
{
	fake_parent_reset();
	fake_clock_start();
	fake_num_fds_errno = injected_errno;

	__real_replace_child(3);

	if (fake_slot_log[3].forks != 0)
		return RUN_FORKED;
	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != EXIT_NO_FDS)
		return RUN_NOT_STOPPED;
	if (fake_slot_log[3].spawns != 1 || fake_sleeps != 0)
		return RUN_RETRIED;
	return RUN_OK;
}

static void expect_refill_stopped(int how)
{
	switch (how) {
	case RUN_OK:
		return;
	case RUN_FORKED:
		BUG("spawn: a spawn went ahead though the fds could not be counted");
	case RUN_NOT_STOPPED:
		BUG("spawn: a spawn that could not count its fds did not stop the run");
	default:
		BUG("spawn: a refill went on after its spawn stopped the run");
	}
}

/* With no way to count its fds spawn_child() cannot check its headroom.
 * When the count fails because they have run out, with EMFILE or
 * ENFILE, it stops the run as it does once the count says there is
 * none: it forks nothing, and the refill neither retries nor backs off. */
static void spawn_stops_the_run_when_the_fds_run_out(void)
{
	static const int out_of_fds[] = { EMFILE, ENFILE };
	unsigned int i;

	injected_errno = 0;
	expect_refill_stopped(run_with_fd_table_full(refill_with_failing_count));

	for (i = 0; i < ARRAY_SIZE(out_of_fds); i++) {
		injected_errno = out_of_fds[i];
		expect_refill_stopped(refill_with_failing_count());
	}
}

/* The line a skipped headroom check is logged with. */
#define HEADROOM_SKIPPED	"skipping the fd headroom check"

/* Any other failure only leaves that spawn unchecked, and a long run is
 * not worth ending for that: the spawn goes ahead, and the skipped check
 * is logged once for the run.  spawn.c latches that line, so this is the
 * one test that fails the count with another errno. */
static void other_count_failures_skip_the_check_and_log_it_once(void)
{
	char *first;

	fake_parent_reset();
	fake_clock_start();

	fake_num_fds_errno = ENOMEM;
	__real_replace_child(3);
	fake_num_fds_errno = ENOENT;
	__real_replace_child(4);

	if (__atomic_load_n(&shm->exit_reason, __ATOMIC_RELAXED) != STILL_RUNNING)
		BUG("spawn: a count that failed for another reason stopped the run");
	if (pids[3] != FAKE_FORK_PID(3) || pids[4] != FAKE_FORK_PID(4))
		BUG("spawn: a count that failed for another reason held up the spawn");
	first = strstr(fake_output_log, HEADROOM_SKIPPED);
	if (first == NULL || strstr(first + 1, HEADROOM_SKIPPED) != NULL)
		BUG("spawn: the skipped headroom check was not logged exactly once");
	if (strstr(fake_output_log, strerror(ENOMEM)) == NULL)
		BUG("spawn: the skipped headroom check was logged without its errno");
}

void get_num_fds_self_check(void);
void get_num_fds_self_check(void)
{
	count_follows_open_fds();
	failed_count_is_reported();
	spawn_stops_the_run_when_the_fds_run_out();
	other_count_failures_skip_the_check_and_log_it_once();

	/* Leave no stopped run for later suites. */
	fake_parent_reset();
}
